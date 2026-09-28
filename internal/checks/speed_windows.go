//go:build windows

package checks

import (
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// linkSpeedMbps takes the negotiated speed from GetAdaptersAddresses, which
// reports it in bits per second. sysNet has no Windows meaning.
//
// Deliberately not WMI: Win32_NetworkAdapter would answer the same question
// through COM, and this check runs every minute — an IP helper call is cheap
// and cannot hang on a broken WMI repository.
func linkSpeedMbps(_, iface string) (float64, bool) {
	adapters, err := adapterAddresses()
	if err != nil {
		return 0, false
	}
	for _, a := range adapters {
		if !strings.EqualFold(windows.UTF16PtrToString(a.FriendlyName), iface) {
			continue
		}
		// A disconnected adapter reports its nominal speed or nothing at
		// all; both are useless, and 0 would read as a dead link.
		if a.TransmitLinkSpeed == 0 || a.TransmitLinkSpeed == ^uint64(0) {
			return 0, false
		}
		return float64(a.TransmitLinkSpeed) / 1e6, true
	}
	return 0, false
}

// adapterAddresses walks the linked list GetAdaptersAddresses returns.
func adapterAddresses() ([]*windows.IpAdapterAddresses, error) {
	size := uint32(15000) // the size Microsoft's own sample starts with
	for range 3 {
		buf := make([]byte, size)
		addr := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])) // #nosec G103 -- documented API layout
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC,
			windows.GAA_FLAG_SKIP_ANYCAST|windows.GAA_FLAG_SKIP_MULTICAST|windows.GAA_FLAG_SKIP_DNS_SERVER,
			0, addr, &size)
		if err == windows.ERROR_BUFFER_OVERFLOW {
			continue // size now holds what is needed
		}
		if err != nil {
			return nil, err
		}
		var out []*windows.IpAdapterAddresses
		for a := addr; a != nil; a = a.Next {
			out = append(out, a)
		}
		return out, nil
	}
	return nil, windows.ERROR_BUFFER_OVERFLOW
}
