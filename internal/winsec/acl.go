package winsec

import (
	"errors"
	"fmt"
	"io/fs"
	"strings"
)

// Package winsec judges Windows file security. Both callers — the config
// file that carries the host token and the local check scripts the agent
// runs as LocalSystem — need the same answer: may anyone but a privileged
// account touch this path?
//
// The judgement lives in this untagged file so it is exercised by the tests
// on Linux as well; only the gathering of owner and DACL is Windows-only
// (acl_windows.go).
//
// agent.conf holds the host token. On Unix that means mode 0600 and root as
// the owner; the Windows equivalent is: the file is owned by a privileged
// account and its DACL grants access to nobody else. The strict reading —
// ANY allow entry for a non-privileged SID is a violation, not just a
// writable one — mirrors 0600, where group and others get no read either.
//
// This matters in practice: %ProgramData% grants the local Users group read
// and execute by default, and a directory created below it inherits that. An
// installer that does not replace the inherited DACL therefore leaves the
// host token readable by every local account, and this check says so instead
// of quietly accepting it.

// Entry is one access control entry, reduced to what the judgement needs.
type Entry struct {
	SID   string
	Mask  uint32
	Allow bool
}

// ErrInsecure means the path may be read or written by an account that is
// not privileged. Callers wrap it in their own sentinel.
var ErrInsecure = errors.New("insecure path")

// privilegedSIDs may appear in the DACL of agent.conf.
//
//	S-1-5-18     LocalSystem — the account the agent service runs as
//	S-1-5-32-544 Administrators
//	S-1-3-0      CREATOR OWNER — an inherited placeholder that resolves to the
//	             file's owner, which this check requires to be privileged anyway
//	S-1-5-80-956008885-…  TrustedInstaller, the owner of files Windows servicing manages
var privilegedSIDs = map[string]string{
	"S-1-5-18":     "LocalSystem",
	"S-1-5-32-544": "Administrators",
	"S-1-3-0":      "CREATOR OWNER",
	"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464": "TrustedInstaller",
}

func privileged(sid string) bool {
	_, ok := privilegedSIDs[strings.ToUpper(strings.TrimSpace(sid))]
	return ok
}

// Evaluate applies the rule above. It never returns a nil error for a
// file it could not judge: an empty owner is a failure, not a pass.
func Evaluate(path, owner string, entries []Entry) error {
	if strings.TrimSpace(owner) == "" {
		return fmt.Errorf("%w: cannot determine owner of %s", ErrInsecure, path)
	}
	if !privileged(owner) {
		return fmt.Errorf("%w: %s is owned by %s, want LocalSystem or Administrators", ErrInsecure, path, owner)
	}
	for _, e := range entries {
		if !e.Allow || privileged(e.SID) {
			continue
		}
		return fmt.Errorf("%w: %s grants access (mask 0x%08x) to %s", ErrInsecure, path, e.Mask, e.SID)
	}
	return nil
}

// EvaluateDir is the part of the directory check that precedes the DACL: the
// path must be a plain directory. A junction, symlink or other reparse point
// would let whoever placed it redirect what the agent writes there — the
// owner and DACL it reports are those of the link, not of where the data
// lands. mode comes from Lstat, which does not follow the link.
func EvaluateDir(path string, mode fs.FileMode) error {
	if mode.Type() != fs.ModeDir {
		return fmt.Errorf("%w: %s is not a plain directory (mode %s) — a junction or link here could redirect the agent's files", ErrInsecure, path, mode.Type())
	}
	return nil
}
