package main

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/INFORENT-GmbH/host-agent/internal/brand"
	"github.com/INFORENT-GmbH/host-agent/internal/buildinfo"
	"github.com/INFORENT-GmbH/host-agent/internal/config"
	"github.com/INFORENT-GmbH/host-agent/internal/hostinfo"
	"github.com/INFORENT-GmbH/host-agent/internal/protocol"
)

// envEnrollToken lets the install one-liner pass the token without putting
// it on the command line (visible in ps and shell history).
const envEnrollToken = "AGENT_ENROLL_TOKEN"

// enrollHTTPClient is replaced in tests.
var enrollHTTPClient = &http.Client{Timeout: 30 * time.Second}

func enroll(ctx context.Context, b brand.Brand, args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("enroll", flag.ContinueOnError)
	fs.SetOutput(stderr)
	gateway := fs.String("url", "", "gateway base URL, e.g. https://agent.example.com")
	token := fs.String("token", "", "enroll token from the portal (or set "+envEnrollToken+")")
	force := fs.Bool("force", false, "replace an existing enrollment")
	channel := fs.String("channel", "", "update channel: stable, testing or off (default: the portal's)")
	localChecks := fs.Bool("local-checks", true, "run local check scripts and MRPE entries")
	// Windows has no apt source to carry the download location, so the setup
	// script passes it here; on Linux it stays empty and unused.
	packageBase := fs.String("package-base", "", "https base the Windows self-update downloads from, e.g. https://apt.example.com")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	// Only an explicit -local-checks touches the opt-in; without the flag a
	// re-enrollment keeps what the host operator configured.
	setFlags := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { setFlags[f.Name] = true })
	if *token == "" {
		*token = getenv(envEnrollToken)
	}
	if !protocol.ValidUpdateChannel(*channel) {
		_, _ = fmt.Fprintf(stderr, "-channel must be one of %s\n", strings.Join(protocol.UpdateChannels, ", "))
		return 2
	}
	if *packageBase != "" {
		if _, err := gatewayBase(*packageBase); err != nil {
			_, _ = fmt.Fprintf(stderr, "-package-base must be https://host, got %q\n", *packageBase)
			return 2
		}
	}
	base, err := gatewayBase(*gateway)
	if err != nil || *token == "" {
		if err != nil {
			_, _ = fmt.Fprintln(stderr, err)
		}
		_, _ = fmt.Fprintf(stderr, "usage: %s enroll -url https://<gateway> -token <enroll token>\n", b.Name())
		return 2
	}

	cfg, err := config.Load(b.ConfigFile())
	switch {
	case errors.Is(err, os.ErrNotExist):
		cfg = config.Default()
	case err != nil:
		_, _ = fmt.Fprintf(stderr, "config error: %v\n", err)
		return 1
	case cfg.Enrolled() && !*force:
		_, _ = fmt.Fprintf(stderr, "already enrolled with %s; use -force to replace it\n", cfg.Server.URL)
		return 1
	}

	info, err := hostinfo.Gather(b.Root)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "host info: %v\n", err)
		return 1
	}
	req := &protocol.EnrollRequest{
		EnrollToken:   *token,
		AgentVersion:  buildinfo.Version,
		Brand:         b.Key,
		Hostname:      info.Hostname,
		MachineID:     info.MachineID,
		OS:            info.OS,
		UpdateChannel: *channel,
	}
	resp, err := postEnroll(ctx, base, req)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "enroll failed: %v\n", err)
		return 1
	}

	// Local opt-ins and log level survive a re-enrollment — unless the
	// operator asked for a different one on the command line.
	if setFlags["local-checks"] {
		cfg.Local.LocalChecks = *localChecks
	}
	// A re-enrollment without -package-base keeps the configured source: the
	// self-update must not silently switch off because someone re-registered.
	keepBase := cfg.Server.PackageBase
	if *packageBase != "" {
		keepBase = *packageBase
	}
	cfg.Server = config.Server{URL: base, Token: resp.HostToken, PackageBase: keepBase}
	if err := config.Save(b.ConfigFile(), cfg); err != nil {
		_, _ = fmt.Fprintf(stderr, "saving %s: %v\n", b.ConfigFile(), err)
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "enrolled as host %s\nstart the agent: systemctl enable --now %s\n", resp.HostID, b.Unit())
	return 0
}

func gatewayBase(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "https" || u.Host == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" {
		return "", fmt.Errorf("-url must be https://host, got %q", raw)
	}
	return "https://" + u.Host, nil
}

func postEnroll(ctx context.Context, base string, req *protocol.EnrollRequest) (*protocol.EnrollResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/v1/enroll", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	hreq.Header.Set("Content-Type", "application/json")
	hresp, err := enrollHTTPClient.Do(hreq)
	if err != nil {
		return nil, err
	}
	defer func() { _ = hresp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(hresp.Body, 64<<10))
	if err != nil {
		return nil, err
	}
	if hresp.StatusCode != http.StatusOK {
		return nil, enrollError(hresp.StatusCode, data)
	}
	return protocol.DecodeEnrollResponse(data)
}

// enrollError turns the gateway's {code} into something the operator can act
// on. MACHINE_ID_IN_USE is the clone trap: VMs from one template share
// /etc/machine-id, and without this message every enrollment silently replaced
// the previous host.
func enrollError(status int, body []byte) error {
	var e struct {
		Code string `json:"code"`
		Host string `json:"host"`
	}
	_ = json.Unmarshal(body, &e)
	switch e.Code {
	case "INVALID_TOKEN":
		return errors.New("the enroll token is invalid or expired — create a new one in the portal")
	case "NOT_ENTITLED":
		return errors.New("server monitoring is not enabled for this tenant — ask support")
	case "LIMIT_REACHED":
		return errors.New("the tenant's server limit is reached — remove a host in the portal or ask support")
	case "MACHINE_ID_IN_USE":
		return fmt.Errorf("host %q already uses this machine-id — this machine looks like a clone; "+
			"give it its own id with: rm -f /etc/machine-id /var/lib/dbus/machine-id && systemd-machine-id-setup", e.Host)
	case "RATE_LIMITED":
		return errors.New("too many enrollments from this address — wait a minute and try again")
	}
	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		return errors.New("the enroll token is invalid or expired — create a new one in the portal")
	}
	return fmt.Errorf("gateway answered HTTP %d", status)
}
