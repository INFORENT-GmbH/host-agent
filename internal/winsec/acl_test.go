package winsec

import (
	"errors"
	"testing"
)

// The Windows security check cannot run on our CI, so its judgement is
// tested here with the descriptors Windows actually produces.
func TestEvaluate(t *testing.T) {
	const (
		system     = "S-1-5-18"
		admins     = "S-1-5-32-544"
		users      = "S-1-5-32-545"
		someUser   = "S-1-5-21-1111111111-2222222222-3333333333-1001"
		fullAccess = 0x1f01ff
		readOnly   = 0x1200a9
	)
	for _, tc := range []struct {
		name    string
		owner   string
		entries []Entry
		wantErr bool
	}{
		{
			name:  "what the installer must leave behind",
			owner: system,
			entries: []Entry{
				{SID: system, Mask: fullAccess, Allow: true},
				{SID: admins, Mask: fullAccess, Allow: true},
			},
		},
		{
			name:  "inherited ProgramData ACL leaks the token to every local account",
			owner: system,
			entries: []Entry{
				{SID: system, Mask: fullAccess, Allow: true},
				{SID: admins, Mask: fullAccess, Allow: true},
				{SID: users, Mask: readOnly, Allow: true},
			},
			wantErr: true,
		},
		{
			name:  "a deny entry never widens access",
			owner: admins,
			entries: []Entry{
				{SID: someUser, Mask: fullAccess, Allow: false},
				{SID: system, Mask: fullAccess, Allow: true},
			},
		},
		{
			name:    "a file an ordinary user owns can be replaced by them",
			owner:   someUser,
			entries: []Entry{{SID: system, Mask: fullAccess, Allow: true}},
			wantErr: true,
		},
		{
			name:    "an unreadable owner is a failure, not a pass",
			owner:   "",
			wantErr: true,
		},
		{
			name:  "CREATOR OWNER resolves to the owner, which is privileged",
			owner: admins,
			entries: []Entry{
				{SID: "S-1-3-0", Mask: fullAccess, Allow: true},
				{SID: system, Mask: fullAccess, Allow: true},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := Evaluate(`C:\ProgramData\acme-agent\agent.conf`, tc.owner, tc.entries)
			if tc.wantErr {
				if !errors.Is(err, ErrInsecure) {
					t.Fatalf("want ErrInsecure, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("want no error, got %v", err)
			}
		})
	}
}

func TestPrivilegedIsCaseInsensitive(t *testing.T) {
	if !privileged("s-1-5-18") {
		t.Fatal("LocalSystem should be privileged regardless of case")
	}
	if privileged("S-1-5-32-545") {
		t.Fatal("the Users group must not count as privileged")
	}
}
