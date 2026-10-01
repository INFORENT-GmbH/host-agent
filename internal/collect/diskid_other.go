//go:build !linux

package collect

// diskIDResolver has no by-id tree to read outside Linux; filesystems carry
// no disk_id label there.
type diskIDResolver struct{}

func newDiskIDResolver() *diskIDResolver { return &diskIDResolver{} }

func (*diskIDResolver) resolve(string) string { return "" }
