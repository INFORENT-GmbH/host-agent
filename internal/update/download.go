package update

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

// maxDownload caps a fetched body. A manifest is tiny and an MSI a few tens of
// MB; this is a sanity bound against a misbehaving host, not a real limit.
const maxDownload = 200 << 20

// httpGet fetches a URL with a timeout and a size cap. It is the default seam
// for the Windows self-update; tests replace Manager.httpGet.
func httpGet(ctx context.Context, rawURL string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", rawURL, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxDownload))
}
