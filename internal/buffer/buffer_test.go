package buffer

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func open(t *testing.T, dir string, maxBytes int64, maxAge time.Duration) *Buffer {
	t.Helper()
	b, err := Open(dir, maxBytes, maxAge)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
	return b
}

func appendN(t *testing.T, b *Buffer, n int, at time.Time) []uint64 {
	t.Helper()
	var seqs []uint64
	for i := 0; i < n; i++ {
		seq, err := b.NextSeq()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := b.Append(seq, at, []byte(fmt.Sprintf(`{"n":%d}`, seq))); err != nil {
			t.Fatal(err)
		}
		seqs = append(seqs, seq)
	}
	return seqs
}

func pending(t *testing.T, b *Buffer) []uint64 {
	t.Helper()
	var seqs []uint64
	if err := b.Pending(func(r Record) error {
		if string(r.Frame) != fmt.Sprintf(`{"n":%d}`, r.Seq) {
			t.Errorf("seq %d frame %q", r.Seq, r.Frame)
		}
		seqs = append(seqs, r.Seq)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return seqs
}

func TestAppendAckReopen(t *testing.T) {
	dir := t.TempDir()
	b := open(t, dir, 1<<30, time.Hour)
	epoch := b.Epoch()
	now := time.Now()
	seqs := appendN(t, b, 5, now)
	if !slices.Equal(seqs, []uint64{1, 2, 3, 4, 5}) {
		t.Fatalf("seqs %v", seqs)
	}
	if err := b.Ack(3); err != nil {
		t.Fatal(err)
	}
	if got := pending(t, b); !slices.Equal(got, []uint64{4, 5}) {
		t.Errorf("pending %v", got)
	}
	_ = b.Close()

	b2 := open(t, dir, 1<<30, time.Hour)
	if b2.Epoch() != epoch {
		t.Error("epoch changed on reopen")
	}
	if got := pending(t, b2); !slices.Equal(got, []uint64{4, 5}) {
		t.Errorf("pending after reopen %v", got)
	}
	seq, _ := b2.NextSeq()
	// The high-water mark reserves a block, so seq jumps past anything a
	// crashed process might have handed out.
	if seq <= 5 {
		t.Errorf("next seq %d after reopen, want > 5", seq)
	}
}

func TestSeqNeverReusedAfterFullAck(t *testing.T) {
	dir := t.TempDir()
	b := open(t, dir, 1<<30, time.Hour)
	appendN(t, b, 3, time.Now())
	// Live frames take seqs without being buffered.
	for i := 0; i < 5; i++ {
		_, _ = b.NextSeq()
	}
	if err := b.Ack(3); err != nil {
		t.Fatal(err)
	}
	_ = b.Close()
	b2 := open(t, dir, 1<<30, time.Hour)
	if seq, _ := b2.NextSeq(); seq <= 8 {
		t.Errorf("seq %d reuses numbers handed out before restart", seq)
	}
}

func TestTornTailIsCut(t *testing.T) {
	dir := t.TempDir()
	b := open(t, dir, 1<<30, time.Hour)
	appendN(t, b, 3, time.Now())
	_ = b.Close()
	segs, _ := filepath.Glob(filepath.Join(dir, "seg-*"))
	f, err := os.OpenFile(segs[len(segs)-1], os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.Write([]byte{0, 0, 0, 0, 0, 0, 0, 9, 1, 2}) // half a header
	_ = f.Close()

	b2 := open(t, dir, 1<<30, time.Hour)
	if got := pending(t, b2); !slices.Equal(got, []uint64{1, 2, 3}) {
		t.Errorf("pending %v", got)
	}
	seq, _ := b2.NextSeq()
	if _, err := b2.Append(seq, time.Now(), []byte(fmt.Sprintf(`{"n":%d}`, seq))); err != nil {
		t.Fatal(err)
	}
	if got := pending(t, b2); len(got) != 4 {
		t.Errorf("append after repair: %v", got)
	}
}

func TestSizeLimitDropsOldestSegments(t *testing.T) {
	dir := t.TempDir()
	b := open(t, dir, 3*segmentMaxSize, 24*time.Hour)
	frame := make([]byte, 512*1024)
	now := time.Now()
	for i := 0; i < 40; i++ {
		seq, _ := b.NextSeq()
		if _, err := b.Append(seq, now, frame); err != nil {
			t.Fatal(err)
		}
	}
	size, dropped := b.Stats()
	if size > 3*segmentMaxSize || dropped == 0 {
		t.Errorf("size %d dropped %d", size, dropped)
	}
}

func TestAgeLimitDropsOldestSegments(t *testing.T) {
	dir := t.TempDir()
	b := open(t, dir, 1<<30, time.Hour)
	frame := make([]byte, segmentMaxSize/2)
	old := time.Now().Add(-3 * time.Hour)
	for i := 0; i < 4; i++ {
		seq, _ := b.NextSeq()
		if _, err := b.Append(seq, old, frame); err != nil {
			t.Fatal(err)
		}
	}
	seq, _ := b.NextSeq()
	n, err := b.Append(seq, time.Now(), frame)
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Error("records older than maxAge were kept")
	}
}

func TestMissingEpochStartsFresh(t *testing.T) {
	dir := t.TempDir()
	b := open(t, dir, 1<<30, time.Hour)
	appendN(t, b, 3, time.Now())
	epoch := b.Epoch()
	_ = b.Close()
	if err := os.Remove(filepath.Join(dir, "epoch")); err != nil {
		t.Fatal(err)
	}
	b2 := open(t, dir, 1<<30, time.Hour)
	if b2.Epoch() == epoch || len(pending(t, b2)) != 0 {
		t.Error("lost epoch must start a new counter without old records")
	}
	if seq, _ := b2.NextSeq(); seq != 1 {
		t.Errorf("new epoch starts at %d", seq)
	}
}

func TestAppendRejectsOldSeq(t *testing.T) {
	b := open(t, t.TempDir(), 1<<30, time.Hour)
	appendN(t, b, 2, time.Now())
	if _, err := b.Append(2, time.Now(), []byte("x")); err == nil {
		t.Error("out-of-order append accepted")
	}
}
