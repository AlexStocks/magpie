package cli

import (
	"context"
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/yetone/magpie/internal/proc"
)

// statusListener is an OS-observed listener, not a reply from the gateway.
// The port may be bound on a different interface from the URL being probed.
type statusListener struct {
	Port   int    `json:"port"`
	PID    int    `json:"pid"`
	Name   string `json:"name,omitempty"`
	Magpie bool   `json:"magpie"`
}

var statusPortHolder = proc.PortHolder

// statusListenerAt only inspects a loopback target. A local listener says
// nothing about a remote --addr, and a saved gateway.json may be stale.
func statusListenerAt(base string, probeErr error) (*statusListener, string) {
	u, err := url.Parse(base)
	if err != nil {
		return nil, ""
	}
	host := u.Hostname()
	ip := net.ParseIP(host)
	if !strings.EqualFold(host, "localhost") && (ip == nil || !ip.IsLoopback()) {
		return nil, ""
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 {
		return nil, ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	h, ok := statusPortHolder(ctx, port)
	if !ok || h.PID <= 0 {
		return nil, ""
	}
	l := &statusListener{Port: port, PID: h.PID, Name: h.Name, Magpie: proc.RunsMagpie(h.PID, h.Path)}
	if h.Path == "" {
		l.Magpie = proc.IsMagpie(h.Name)
	}
	if !l.Magpie {
		return l, ""
	}
	if e, ok := errors.AsType[*net.OpError](probeErr); ok && e.Op == "dial" {
		return l, "magpie holds the port, but the connection failed; check its listen address and local firewall or security rules"
	}
	// The HTTP client's deadline can expire before the dialer returns
	// a net.OpError. That alone does not tell a dropped connection from
	// an accepted one whose HTTP response is slow.
	if _, opError := errors.AsType[*net.OpError](probeErr); !opError {
		if e, ok := errors.AsType[net.Error](probeErr); ok && e.Timeout() {
			return l, "magpie holds the port, but the request timed out; check its listen address, local firewall or security rules, and gateway logs"
		}
	}
	return l, "magpie holds the port, but did not answer as a gateway; check its listen address and logs"
}
