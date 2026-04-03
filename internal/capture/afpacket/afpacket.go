// Package afpacket implements a pure-Go AF_PACKET capture backend using
// raw sockets. It does not depend on libpcap or gopacket.
package afpacket

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/netcap/netcap/internal/capture"
)

// Fanout type constants matching the Linux kernel values.
const (
	fanoutHash = 0
	fanoutLB   = 1
	fanoutCPU  = 2
)

// Config holds the configuration for an AF_PACKET capturer.
type Config struct {
	// Interface is the network interface name to capture on (e.g. "eth0").
	Interface string
	// NumQueues is the number of parallel capture sockets/goroutines.
	// Defaults to 1 if <= 0.
	NumQueues int
	// BufferSizeMB is the per-socket receive buffer size in megabytes.
	// Defaults to 64 if <= 0.
	BufferSizeMB int
	// SnapLength is the maximum number of bytes captured per packet.
	// Defaults to 65535 if <= 0.
	SnapLength int
	// BPFFilter is a raw BPF filter expression (currently unused placeholder).
	BPFFilter string
	// FanoutType controls how packets are distributed across queues.
	// Supported values: "hash", "lb", "cpu". Defaults to "hash".
	FanoutType string
	// FanoutGroupID is the fanout group identifier. All sockets in the
	// same group share traffic. Defaults to 1 if <= 0.
	FanoutGroupID int
	// OutputBuffer is the capacity of the output packet channel.
	// Defaults to 4096 if <= 0.
	OutputBuffer int
}

// defaults fills in zero-value fields with sensible defaults.
func (c *Config) defaults() {
	if c.NumQueues <= 0 {
		c.NumQueues = 1
	}
	if c.BufferSizeMB <= 0 {
		c.BufferSizeMB = 64
	}
	if c.SnapLength <= 0 {
		c.SnapLength = 65535
	}
	if c.FanoutType == "" {
		c.FanoutType = "hash"
	}
	if c.FanoutGroupID <= 0 {
		c.FanoutGroupID = 1
	}
	if c.OutputBuffer <= 0 {
		c.OutputBuffer = 4096
	}
}

// AFPacketCapturer captures packets using Linux AF_PACKET raw sockets.
type AFPacketCapturer struct {
	cfg    Config
	fds    []int
	output chan capture.Packet
	stats  struct {
		received atomic.Uint64
		dropped  atomic.Uint64
	}
	logger *slog.Logger
	wg     sync.WaitGroup
	cancel context.CancelFunc
}

// New creates a new AFPacketCapturer with the given config and logger.
// If logger is nil, a default logger is used.
func New(cfg Config, logger *slog.Logger) *AFPacketCapturer {
	cfg.defaults()
	if logger == nil {
		logger = slog.Default()
	}
	return &AFPacketCapturer{
		cfg:    cfg,
		logger: logger,
	}
}

// Name returns the capture backend name.
func (a *AFPacketCapturer) Name() string {
	return "afpacket"
}

// Stats returns the current capture statistics.
func (a *AFPacketCapturer) Stats() capture.Stats {
	return capture.Stats{
		PacketsReceived: a.stats.received.Load(),
		PacketsDropped:  a.stats.dropped.Load(),
	}
}

// Start opens AF_PACKET sockets and begins capturing packets.
// Packets are delivered on the returned channel until ctx is cancelled
// or Close is called.
func (a *AFPacketCapturer) Start(ctx context.Context) (<-chan capture.Packet, error) {
	if a.cfg.Interface == "" {
		return nil, errors.New("afpacket: interface name is required")
	}

	iface, err := net.InterfaceByName(a.cfg.Interface)
	if err != nil {
		return nil, fmt.Errorf("afpacket: lookup interface %q: %w", a.cfg.Interface, err)
	}

	fanoutType, err := parseFanoutType(a.cfg.FanoutType)
	if err != nil {
		return nil, err
	}

	ctx, a.cancel = context.WithCancel(ctx)
	a.output = make(chan capture.Packet, a.cfg.OutputBuffer)
	a.fds = make([]int, 0, a.cfg.NumQueues)

	bufBytes := a.cfg.BufferSizeMB * 1024 * 1024

	for i := 0; i < a.cfg.NumQueues; i++ {
		fd, err := a.openSocket(iface.Index, bufBytes)
		if err != nil {
			a.closeAllFDs()
			return nil, fmt.Errorf("afpacket: open socket %d: %w", i, err)
		}
		a.fds = append(a.fds, fd)

		// Enable fanout when using multiple queues.
		if a.cfg.NumQueues > 1 {
			fanoutArg := a.cfg.FanoutGroupID | (fanoutType << 16)
			if err := unix.SetsockoptInt(fd, unix.SOL_PACKET, unix.PACKET_FANOUT, fanoutArg); err != nil {
				a.closeAllFDs()
				return nil, fmt.Errorf("afpacket: set fanout on socket %d: %w", i, err)
			}
		}

		a.wg.Add(1)
		go a.captureLoop(ctx, fd, i)
	}

	// Closer goroutine: waits for all capture loops to finish, then closes
	// the output channel.
	go func() {
		a.wg.Wait()
		close(a.output)
	}()

	return a.output, nil
}

// Close stops capturing and releases all sockets.
func (a *AFPacketCapturer) Close() error {
	if a.cancel != nil {
		a.cancel()
	}
	a.wg.Wait()
	a.closeAllFDs()
	return nil
}

// openSocket creates and configures a single AF_PACKET raw socket.
func (a *AFPacketCapturer) openSocket(ifIndex, bufBytes int) (int, error) {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return -1, fmt.Errorf("socket: %w", err)
	}

	sa := &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ALL),
		Ifindex:  ifIndex,
	}
	if err := unix.Bind(fd, sa); err != nil {
		unix.Close(fd)
		return -1, fmt.Errorf("bind: %w", err)
	}

	// Set the receive buffer size.
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, bufBytes); err != nil {
		unix.Close(fd)
		return -1, fmt.Errorf("set SO_RCVBUF: %w", err)
	}

	return fd, nil
}

// captureLoop reads packets from a single socket until the context is done.
func (a *AFPacketCapturer) captureLoop(ctx context.Context, fd int, queueID int) {
	defer a.wg.Done()

	buf := make([]byte, a.cfg.SnapLength)
	pollFDs := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Poll with a 100ms timeout so we periodically check the context.
		n, err := unix.Poll(pollFDs, 100)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			a.logger.Error("poll error", "queue", queueID, "err", err)
			return
		}
		if n == 0 {
			// Timeout, loop back to check context.
			continue
		}

		nRead, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if errors.Is(err, unix.EINTR) || errors.Is(err, unix.EAGAIN) {
				continue
			}
			a.logger.Error("recvfrom error", "queue", queueID, "err", err)
			return
		}
		if nRead == 0 {
			continue
		}

		// Copy the data so the buffer can be reused immediately.
		data := make([]byte, nRead)
		copy(data, buf[:nRead])

		pkt := capture.Packet{
			Data:       data,
			Timestamp:  time.Now(),
			CaptureLen: nRead,
			OrigLen:    nRead,
		}

		select {
		case a.output <- pkt:
			a.stats.received.Add(1)
		default:
			// Channel full, drop the packet.
			a.stats.dropped.Add(1)
		}
	}
}

// closeAllFDs closes all open file descriptors.
func (a *AFPacketCapturer) closeAllFDs() {
	for _, fd := range a.fds {
		unix.Close(fd)
	}
	a.fds = nil
}

// parseFanoutType converts a string fanout type to the Linux kernel constant.
func parseFanoutType(s string) (int, error) {
	switch s {
	case "hash":
		return fanoutHash, nil
	case "lb":
		return fanoutLB, nil
	case "cpu":
		return fanoutCPU, nil
	default:
		return 0, fmt.Errorf("afpacket: unsupported fanout type %q (valid: hash, lb, cpu)", s)
	}
}

// htons converts a 16-bit value from host byte order to network byte order.
func htons(v uint16) uint16 {
	b := *(*[2]byte)(unsafe.Pointer(&v))
	return binary.BigEndian.Uint16(b[:])
}
