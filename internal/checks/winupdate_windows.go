//go:build windows

package checks

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"time"

	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
)

// searchTimeout bounds the COM call. An offline search reads the local
// metadata cache and normally takes seconds, but a corrupted data store can
// make it hang, and it must not stall the check tick forever.
const searchTimeout = 5 * time.Minute

// searchPendingUpdates asks the Windows Update agent what is not installed
// yet. Everything runs on one locked OS thread: COM apartments belong to a
// thread, and Go would otherwise move the goroutine between threads between
// two calls.
func searchPendingUpdates(ctx context.Context) ([]winUpdate, error) {
	ctx, cancel := context.WithTimeout(ctx, searchTimeout)
	defer cancel()

	type result struct {
		updates []winUpdate
		err     error
	}
	done := make(chan result, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		u, err := searchOnThread()
		done <- result{u, err}
	}()
	select {
	case r := <-done:
		return r.updates, r.err
	case <-ctx.Done():
		// The goroutine finishes on its own; it holds no lock of ours.
		return nil, fmt.Errorf("Windows Update search timed out after %s", searchTimeout)
	}
}

func searchOnThread() (updates []winUpdate, err error) {
	defer func() {
		// The go-ole helpers panic on unexpected COM results, and a panic in
		// a check must not take the agent down.
		if r := recover(); r != nil {
			err = fmt.Errorf("Windows Update search failed: %v", r)
		}
	}()

	// S_FALSE means this thread's apartment was already initialised,
	// RPC_E_CHANGED_MODE that it was initialised with a different model.
	// Both are usable; only in the first case is the matching
	// CoUninitialize ours to call.
	const sFalse, rpcChangedMode = 1, 0x80010106
	ours := true
	if err := ole.CoInitializeEx(0, ole.COINIT_APARTMENTTHREADED|ole.COINIT_DISABLE_OLE1DDE); err != nil {
		var oleErr *ole.OleError
		if !errors.As(err, &oleErr) {
			return nil, err
		}
		switch oleErr.Code() {
		case sFalse:
		case rpcChangedMode:
			ours = false
		default:
			return nil, err
		}
	}
	if ours {
		defer ole.CoUninitialize()
	}

	session, err := oleutil.CreateObject("Microsoft.Update.Session")
	if err != nil {
		return nil, fmt.Errorf("creating the update session: %w", err)
	}
	defer session.Release()
	dispatch, err := session.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		return nil, err
	}
	defer dispatch.Release()

	searcherVar, err := oleutil.CallMethod(dispatch, "CreateUpdateSearcher")
	if err != nil {
		return nil, fmt.Errorf("creating the update searcher: %w", err)
	}
	searcher := searcherVar.ToIDispatch()
	defer searcher.Release()

	// Offline: read the metadata the Windows Update client already has. The
	// host refreshes it on its own schedule — the agent must not start
	// network traffic or change any update state (same rule as apt).
	if _, err := oleutil.PutProperty(searcher, "Online", false); err != nil {
		return nil, fmt.Errorf("switching the searcher offline: %w", err)
	}

	searchVar, err := oleutil.CallMethod(searcher, "Search", "IsInstalled=0 and Type='Software' and IsHidden=0")
	if err != nil {
		return nil, fmt.Errorf("searching for updates: %w", err)
	}
	searchResult := searchVar.ToIDispatch()
	defer searchResult.Release()

	updatesVar, err := oleutil.GetProperty(searchResult, "Updates")
	if err != nil {
		return nil, err
	}
	list := updatesVar.ToIDispatch()
	defer list.Release()

	countVar, err := oleutil.GetProperty(list, "Count")
	if err != nil {
		return nil, err
	}
	count := int(countVar.Val)
	out := make([]winUpdate, 0, count)
	for i := 0; i < count; i++ {
		itemVar, err := oleutil.GetProperty(list, "Item", i)
		if err != nil {
			return nil, err
		}
		item := itemVar.ToIDispatch()
		u := winUpdate{
			Title:      stringProperty(item, "Title"),
			Severity:   stringProperty(item, "MsrcSeverity"),
			Downloaded: boolProperty(item, "IsDownloaded"),
		}
		item.Release()
		out = append(out, u)
	}
	return out, nil
}

func stringProperty(d *ole.IDispatch, name string) string {
	v, err := oleutil.GetProperty(d, name)
	if err != nil {
		return ""
	}
	defer func() { _ = v.Clear() }()
	s, _ := v.Value().(string)
	return s
}

func boolProperty(d *ole.IDispatch, name string) bool {
	v, err := oleutil.GetProperty(d, name)
	if err != nil {
		return false
	}
	defer func() { _ = v.Clear() }()
	b, _ := v.Value().(bool)
	return b
}
