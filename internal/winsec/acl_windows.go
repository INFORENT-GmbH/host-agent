//go:build windows

package winsec

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// CheckPath reads the owner and DACL of path and applies Evaluate. Go's
// os.FileInfo is no help here: it reports 0666 for every readable file, so
// the Unix mode check has no Windows equivalent — the DACL is the only
// honest source.
func CheckPath(path string) error {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("%w: reading the security descriptor of %s: %v", ErrInsecure, path, err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("%w: reading the owner of %s: %v", ErrInsecure, path, err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("%w: reading the DACL of %s: %v", ErrInsecure, path, err)
	}
	// A NULL DACL is not "no permissions" but "everyone, everything".
	if dacl == nil {
		return fmt.Errorf("%w: %s has no DACL, which grants everyone full access", ErrInsecure, path)
	}
	entries, err := aclEntries(dacl)
	if err != nil {
		return fmt.Errorf("%w: reading the DACL of %s: %v", ErrInsecure, path, err)
	}
	return Evaluate(path, owner.String(), entries)
}

// aclEntries flattens a DACL. Only allow entries carry a SID the judgement
// looks at; deny entries can never widen access.
func aclEntries(dacl *windows.ACL) ([]Entry, error) {
	out := make([]Entry, 0, dacl.AceCount)
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return nil, err
		}
		// The SID follows the fixed part of the ACE; SidStart is its first
		// byte, which is why this needs unsafe — the Windows API offers no
		// other way to walk an ACL.
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)) // #nosec G103 -- documented ACE layout
		out = append(out, Entry{
			SID:   sid.String(),
			Mask:  uint32(ace.Mask),
			Allow: ace.Header.AceType == windows.ACCESS_ALLOWED_ACE_TYPE,
		})
	}
	return out, nil
}
