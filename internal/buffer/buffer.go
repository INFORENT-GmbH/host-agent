// Package buffer stores outgoing frames on disk until the gateway
// acknowledges them, so a network outage or an agent restart loses nothing
// within the configured size and age limits.
//
// Layout of the state directory (0700):
//
//	epoch        16 hex chars; a new one means a new seq counter
//	seq-hw       sequence high-water mark (see NextSeq)
//	acked        highest seq the gateway confirmed
//	seg-<first>  append-only segment files of records
//
// Record: seq uint64 | unix ms int64 | length uint32 | crc32 uint32 |
// payload (big endian). A torn write at the end of the newest segment is cut
// off when the buffer is opened.
package buffer

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	headerSize     = 24
	segmentMaxSize = 4 << 20
	// seqReserve: the high-water mark is written once per block, not per
	// frame. After a crash seq continues above the mark, so no number the
	// gateway may already have seen (live frames are not buffered) is reused.
	seqReserve = 1000
)

// ErrCorrupt reports an unreadable record.
var ErrCorrupt = errors.New("corrupt buffer record")

// Record is one buffered frame.
type Record struct {
	Seq   uint64
	At    time.Time
	Frame []byte
}

type segment struct {
	path        string
	first, last uint64
	count       int
	size        int64
	newest      time.Time
}

// Buffer is safe for concurrent use.
type Buffer struct {
	dir      string
	maxBytes int64
	maxAge   time.Duration

	mu       sync.Mutex
	epoch    string
	nextSeq  uint64
	seqHW    uint64
	acked    uint64
	segments []*segment
	active   *os.File
	dropped  uint64
}

// Open loads or creates the buffer in dir.
func Open(dir string, maxBytes int64, maxAge time.Duration) (*Buffer, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	b := &Buffer{dir: dir, maxBytes: maxBytes, maxAge: maxAge}

	epoch, err := readString(b.file("epoch"))
	if errors.Is(err, os.ErrNotExist) || !validEpoch(epoch) {
		// A new counter: whatever old segments exist belong to the old epoch
		// and must not be resent under the new one.
		if err := b.reset(); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	} else {
		b.epoch = epoch
		b.seqHW = readUint(b.file("seq-hw"))
		b.acked = readUint(b.file("acked"))
		if err := b.loadSegments(); err != nil {
			return nil, err
		}
	}

	b.nextSeq = max(b.seqHW, b.acked) + 1
	if n := len(b.segments); n > 0 {
		b.nextSeq = max(b.nextSeq, b.segments[n-1].last+1)
	}
	return b, nil
}

// Epoch identifies the seq counter (hello.seqEpoch).
func (b *Buffer) Epoch() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.epoch
}

// NextSeq hands out the next sequence number, persisting the high-water
// mark in blocks.
func (b *Buffer) NextSeq() (uint64, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	seq := b.nextSeq
	if seq >= b.seqHW {
		hw := seq + seqReserve
		if err := writeAtomic(b.file("seq-hw"), strconv.FormatUint(hw, 10)); err != nil {
			return 0, err
		}
		b.seqHW = hw
	}
	b.nextSeq++
	return seq, nil
}

// Append stores a frame durably (fsync) and enforces the limits. It returns
// how many old records were dropped to make room.
func (b *Buffer) Append(seq uint64, at time.Time, frame []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if n := len(b.segments); n > 0 && seq <= b.segments[n-1].last {
		return 0, fmt.Errorf("seq %d not above last buffered %d", seq, b.segments[n-1].last)
	}
	seg, err := b.writable(seq, int64(headerSize+len(frame)))
	if err != nil {
		return 0, err
	}
	var hdr [headerSize]byte
	binary.BigEndian.PutUint64(hdr[0:], seq)
	binary.BigEndian.PutUint64(hdr[8:], uint64(at.UnixMilli())) // #nosec G115 -- unix ms is positive
	binary.BigEndian.PutUint32(hdr[16:], uint32(len(frame)))    // #nosec G115 -- frames are bounded by MaxMessageBytes
	binary.BigEndian.PutUint32(hdr[20:], crc32.ChecksumIEEE(frame))
	if _, err := b.active.Write(append(hdr[:], frame...)); err != nil {
		return 0, err
	}
	if err := b.active.Sync(); err != nil {
		return 0, err
	}
	seg.last, seg.newest = seq, at
	seg.count++
	seg.size += int64(headerSize + len(frame))
	return b.enforceLimits(at)
}

// Ack drops everything up to and including seq.
func (b *Buffer) Ack(seq uint64) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if seq <= b.acked {
		return nil
	}
	b.acked = seq
	if err := writeAtomic(b.file("acked"), strconv.FormatUint(seq, 10)); err != nil {
		return err
	}
	for len(b.segments) > 0 && b.segments[0].last <= seq {
		if err := b.removeFirst(); err != nil {
			return err
		}
	}
	return nil
}

// Pending calls fn for every unacknowledged record in order. fn runs
// without the lock held, so it may block on the network.
func (b *Buffer) Pending(fn func(Record) error) error {
	b.mu.Lock()
	acked := b.acked
	paths := make([]string, len(b.segments))
	for i, s := range b.segments {
		paths[i] = s.path
	}
	b.mu.Unlock()

	for _, p := range paths {
		err := readSegment(p, func(r Record) error {
			if r.Seq <= acked {
				return nil
			}
			return fn(r)
		})
		// A segment acked and removed meanwhile is fine.
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil && !errors.Is(err, ErrCorrupt) {
			return err
		}
	}
	return nil
}

// Stats reports the buffer's size and how many records the limits dropped
// since start.
func (b *Buffer) Stats() (bytes int64, dropped uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, s := range b.segments {
		bytes += s.size
	}
	return bytes, b.dropped
}

// Close releases the active segment.
func (b *Buffer) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.active == nil {
		return nil
	}
	err := b.active.Close()
	b.active = nil
	return err
}

// ---------------------------------------------------------------- internals

func (b *Buffer) file(name string) string { return filepath.Join(b.dir, name) }

func (b *Buffer) reset() error {
	for _, name := range b.segmentNames() {
		if err := os.Remove(b.file(name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	raw := make([]byte, 8)
	if _, err := rand.Read(raw); err != nil {
		return err
	}
	b.epoch = hex.EncodeToString(raw)
	b.seqHW, b.acked, b.segments = 0, 0, nil
	// epoch last: a crash in between leaves no valid epoch, so the next
	// start resets again instead of pairing a new epoch with old counters.
	for _, kv := range [][2]string{{"seq-hw", "0"}, {"acked", "0"}, {"epoch", b.epoch}} {
		if err := writeAtomic(b.file(kv[0]), kv[1]); err != nil {
			return err
		}
	}
	return nil
}

func (b *Buffer) segmentNames() []string {
	entries, _ := os.ReadDir(b.dir)
	var names []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "seg-") && !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	slices.Sort(names) // zero-padded first seq sorts numerically
	return names
}

func (b *Buffer) loadSegments() error {
	names := b.segmentNames()
	for i, name := range names {
		path := b.file(name)
		seg := &segment{path: path}
		var goodSize int64
		err := readSegment(path, func(r Record) error {
			if seg.first == 0 {
				seg.first = r.Seq
			}
			seg.last, seg.newest = r.Seq, r.At
			seg.count++
			goodSize += int64(headerSize + len(r.Frame))
			return nil
		})
		switch {
		case errors.Is(err, ErrCorrupt) && i == len(names)-1:
			// Torn write from a crash: keep the intact prefix.
			if err := os.Truncate(path, goodSize); err != nil {
				return err
			}
		case errors.Is(err, ErrCorrupt):
			// Corruption in the middle: the rest of this file is lost, the
			// following segments are still valid.
		case err != nil:
			return err
		}
		seg.size = goodSize
		if seg.first == 0 || seg.last <= b.acked {
			if err := os.Remove(path); err != nil {
				return err
			}
			continue
		}
		b.segments = append(b.segments, seg)
	}
	return nil
}

// writable returns the segment to append to, starting a new one when the
// current one is full.
func (b *Buffer) writable(seq uint64, n int64) (*segment, error) {
	if k := len(b.segments); k > 0 && b.active != nil && b.segments[k-1].size+n <= segmentMaxSize {
		return b.segments[k-1], nil
	}
	if k := len(b.segments); k > 0 && b.active == nil && b.segments[k-1].size+n <= segmentMaxSize {
		f, err := os.OpenFile(b.segments[k-1].path, os.O_WRONLY|os.O_APPEND, 0o600) // #nosec G304 -- own state dir
		if err != nil {
			return nil, err
		}
		b.active = f
		return b.segments[k-1], nil
	}
	if b.active != nil {
		if err := b.active.Close(); err != nil {
			return nil, err
		}
		b.active = nil
	}
	path := b.file(fmt.Sprintf("seg-%020d", seq))
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- own state dir
	if err != nil {
		return nil, err
	}
	b.active = f
	seg := &segment{path: path, first: seq, last: seq}
	b.segments = append(b.segments, seg)
	return seg, nil
}

func (b *Buffer) enforceLimits(now time.Time) (int, error) {
	dropped := 0
	for len(b.segments) > 1 {
		var total int64
		for _, s := range b.segments {
			total += s.size
		}
		oldest := b.segments[0]
		if total <= b.maxBytes && now.Sub(oldest.newest) <= b.maxAge {
			break
		}
		dropped += oldest.count
		if err := b.removeFirst(); err != nil {
			return dropped, err
		}
	}
	b.dropped += uint64(dropped) // #nosec G115 -- non-negative count
	return dropped, nil
}

func (b *Buffer) removeFirst() error {
	s := b.segments[0]
	if len(b.segments) == 1 && b.active != nil {
		if err := b.active.Close(); err != nil {
			return err
		}
		b.active = nil
	}
	if err := os.Remove(s.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	b.segments = b.segments[1:]
	return nil
}

func readSegment(path string, fn func(Record) error) error {
	f, err := os.Open(path) // #nosec G304 -- own state dir
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	r := bufio.NewReader(f)
	var hdr [headerSize]byte
	for {
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return ErrCorrupt
		}
		n := binary.BigEndian.Uint32(hdr[16:])
		if n > segmentMaxSize {
			return ErrCorrupt
		}
		frame := make([]byte, n)
		if _, err := io.ReadFull(r, frame); err != nil {
			return ErrCorrupt
		}
		if crc32.ChecksumIEEE(frame) != binary.BigEndian.Uint32(hdr[20:]) {
			return ErrCorrupt
		}
		rec := Record{
			Seq:   binary.BigEndian.Uint64(hdr[0:]),
			At:    time.UnixMilli(int64(binary.BigEndian.Uint64(hdr[8:]))), // #nosec G115 -- written from a positive int64
			Frame: frame,
		}
		if err := fn(rec); err != nil {
			return err
		}
	}
}

func validEpoch(s string) bool {
	if len(s) != 16 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil && strings.ToLower(s) == s
}

func readString(path string) (string, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- own state dir
	return strings.TrimSpace(string(b)), err
}

func readUint(path string) uint64 {
	s, err := readString(path)
	if err != nil {
		return 0
	}
	v, _ := strconv.ParseUint(s, 10, 64)
	return v
}

func writeAtomic(path, value string) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600) // #nosec G304 -- own state dir
	if err != nil {
		return err
	}
	if _, err := f.WriteString(value + "\n"); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
