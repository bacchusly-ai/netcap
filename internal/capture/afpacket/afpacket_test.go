package afpacket

import (
	"testing"
)

func TestParseFanoutType(t *testing.T) {
	tests := []struct {
		input   string
		want    int
		wantErr bool
	}{
		{"hash", fanoutHash, false},
		{"lb", fanoutLB, false},
		{"cpu", fanoutCPU, false},
		{"invalid", 0, true},
		{"", 0, true},
	}

	for _, tt := range tests {
		got, err := parseFanoutType(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("parseFanoutType(%q): error = %v, wantErr %v", tt.input, err, tt.wantErr)
			continue
		}
		if got != tt.want {
			t.Errorf("parseFanoutType(%q) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

func TestHtons(t *testing.T) {
	// ETH_P_ALL is 0x0003; htons should produce network byte order.
	result := htons(0x0003)
	// On little-endian (amd64), htons(0x0003) == 0x0300.
	// On big-endian, htons(0x0003) == 0x0003.
	// Either way the round-trip must be stable.
	if htons(result) != 0x0003 {
		t.Errorf("htons round-trip failed: htons(htons(0x0003)) = 0x%04x, want 0x0003", htons(result))
	}
}

func TestConfigDefaults(t *testing.T) {
	var cfg Config
	cfg.defaults()

	if cfg.NumQueues != 1 {
		t.Errorf("NumQueues = %d, want 1", cfg.NumQueues)
	}
	if cfg.BufferSizeMB != 64 {
		t.Errorf("BufferSizeMB = %d, want 64", cfg.BufferSizeMB)
	}
	if cfg.SnapLength != 65535 {
		t.Errorf("SnapLength = %d, want 65535", cfg.SnapLength)
	}
	if cfg.FanoutType != "hash" {
		t.Errorf("FanoutType = %q, want %q", cfg.FanoutType, "hash")
	}
	if cfg.FanoutGroupID != 1 {
		t.Errorf("FanoutGroupID = %d, want 1", cfg.FanoutGroupID)
	}
	if cfg.OutputBuffer != 4096 {
		t.Errorf("OutputBuffer = %d, want 4096", cfg.OutputBuffer)
	}
}

func TestConfigDefaultsPreservesExplicit(t *testing.T) {
	cfg := Config{
		NumQueues:     4,
		BufferSizeMB:  128,
		SnapLength:    1500,
		FanoutType:    "cpu",
		FanoutGroupID: 42,
		OutputBuffer:  8192,
	}
	cfg.defaults()

	if cfg.NumQueues != 4 {
		t.Errorf("NumQueues = %d, want 4", cfg.NumQueues)
	}
	if cfg.BufferSizeMB != 128 {
		t.Errorf("BufferSizeMB = %d, want 128", cfg.BufferSizeMB)
	}
	if cfg.SnapLength != 1500 {
		t.Errorf("SnapLength = %d, want 1500", cfg.SnapLength)
	}
	if cfg.FanoutType != "cpu" {
		t.Errorf("FanoutType = %q, want %q", cfg.FanoutType, "cpu")
	}
	if cfg.FanoutGroupID != 42 {
		t.Errorf("FanoutGroupID = %d, want 42", cfg.FanoutGroupID)
	}
	if cfg.OutputBuffer != 8192 {
		t.Errorf("OutputBuffer = %d, want 8192", cfg.OutputBuffer)
	}
}

func TestNewSetsDefaults(t *testing.T) {
	c := New(Config{Interface: "lo"}, nil)
	if c.cfg.NumQueues != 1 {
		t.Errorf("New did not apply defaults: NumQueues = %d", c.cfg.NumQueues)
	}
	if c.cfg.Interface != "lo" {
		t.Errorf("New lost Interface: got %q", c.cfg.Interface)
	}
}

func TestName(t *testing.T) {
	c := New(Config{}, nil)
	if c.Name() != "afpacket" {
		t.Errorf("Name() = %q, want %q", c.Name(), "afpacket")
	}
}

func TestFanoutConstants(t *testing.T) {
	// Verify the constants match Linux kernel values.
	if fanoutHash != 0 {
		t.Errorf("fanoutHash = %d, want 0", fanoutHash)
	}
	if fanoutLB != 1 {
		t.Errorf("fanoutLB = %d, want 1", fanoutLB)
	}
	if fanoutCPU != 2 {
		t.Errorf("fanoutCPU = %d, want 2", fanoutCPU)
	}
}
