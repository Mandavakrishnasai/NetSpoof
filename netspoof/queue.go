package netspoof

import (
	"context"
	"errors"
	"sync"
)

type packetWriter interface {
	WritePacketData([]byte) error
}

// TxQueue serialises all raw packet writes onto a single goroutine.
// Packet handles are not safe for concurrent writes; this removes the race.
type TxQueue struct {
	handle packetWriter
	ch     chan []byte
	wg     sync.WaitGroup
	closed bool
	mu     sync.Mutex
}

var ErrQueueClosed = errors.New("tx queue closed")

func NewTxQueue(handle packetWriter, buffer int) *TxQueue {
	if buffer <= 0 {
		buffer = 1024
	}
	return &TxQueue{
		handle: handle,
		ch:     make(chan []byte, buffer),
	}
}

func (q *TxQueue) Run(ctx context.Context) {
	q.wg.Add(1)
	go func() {
		defer q.wg.Done()
		for pkt := range q.ch {
			_ = q.handle.WritePacketData(pkt)
		}
	}()
}

func (q *TxQueue) Send(pkt []byte) error {
	q.mu.Lock()
	if q.closed {
		q.mu.Unlock()
		return ErrQueueClosed
	}
	q.mu.Unlock()

	// copy so the caller can reuse its buffer
	cp := make([]byte, len(pkt))
	copy(cp, pkt)

	select {
	case q.ch <- cp:
		return nil
	default:
		// queue full — drop rather than block
		return errors.New("tx queue full")
	}
}

func (q *TxQueue) Close() {
	q.mu.Lock()
	if q.closed {
		q.mu.Unlock()
		return
	}
	q.closed = true
	close(q.ch)
	q.mu.Unlock()
	q.wg.Wait()
}
