// Package util provides shared utilities for the netcap project.
package util

import "sync"

const defaultBufferSize = 9000

var bufferPool = sync.Pool{
	New: func() any {
		b := make([]byte, defaultBufferSize)
		return &b
	},
}

// GetBuffer retrieves a 9000-byte buffer from the pool.
// The caller must call PutBuffer when done.
func GetBuffer() *[]byte {
	return bufferPool.Get().(*[]byte)
}

// PutBuffer returns a buffer to the pool.
// The buffer is reset to its full 9000-byte capacity.
func PutBuffer(buf *[]byte) {
	if buf == nil {
		return
	}
	*buf = (*buf)[:defaultBufferSize]
	bufferPool.Put(buf)
}
