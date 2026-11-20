package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/yetone/magpie/internal/proc"
)

func TestStatusKeepsReadFailureAfterRecognizingMagpie(t *testing.T) {
	t.Setenv("MAGPIE_ADDR", "127.0.0.1:1")
	previous := http.DefaultTransport
	transport := previous.(*http.Transport).Clone()
	var writers sync.WaitGroup
	transport.DialContext = func(context.Context, string, string) (net.Conn, error) {
		client, server := net.Pipe()
		writers.Go(func() {
			defer server.Close()
			request, err := http.ReadRequest(bufio.NewReader(server))
			if err != nil {
				t.Error(err)
				return
			}
			request.Body.Close()
			body := `{"name":"magpie","version":"test"}`
			// The JSON identifies magpie, but the chunked HTTP body is
			// truncated: there is no terminating zero-length chunk.
			if _, err := fmt.Fprintf(server, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n%x\r\n%s\r\n", len(body), body); err != nil {
				t.Error(err)
			}
		})
		return client, nil
	}
	http.DefaultTransport = transport
	t.Cleanup(func() { http.DefaultTransport = previous; transport.CloseIdleConnections(); writers.Wait() })
	for _, args := range [][]string{{"status", "--json"}, {"status"}} {
		out, err := runOut(t, args...)
		if err != nil {
			t.Fatal(err)
		}
		if len(args) == 1 {
			if !strings.Contains(out, "unexpected EOF") {
				t.Fatalf("text status dropped the failed body read: %s", out)
			}
			continue
		}
		var got status
		if err := json.Unmarshal([]byte(out), &got); err != nil {
			t.Fatal(err)
		}
		if !got.Running || !strings.Contains(got.Error, "unexpected EOF") {
			t.Fatalf("keep legacy recognition and the body-read failure: %s", out)
		}
	}
}

// A failed request is not evidence that no gateway process is listening.
// Keep the connection error so a watchdog can distinguish it from a reply
// from another HTTP server, without guessing that every timeout is a firewall.
func TestStatusKeepsConnectionFailure(t *testing.T) {
	t.Setenv("MAGPIE_ADDR", "127.0.0.1:1")
	previous := http.DefaultTransport
	transport := previous.(*http.Transport).Clone()
	transport.DialContext = func(context.Context, string, string) (net.Conn, error) {
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: os.ErrDeadlineExceeded}
	}
	http.DefaultTransport = transport
	t.Cleanup(func() {
		http.DefaultTransport = previous
		transport.CloseIdleConnections()
	})
	out, err := runOut(t, "status", "--json")
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Running bool   `json:"running"`
		Error   string `json:"error"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatal(err)
	}
	if got.Running || !strings.Contains(got.Error, "i/o timeout") {
		t.Fatalf("a failed connection must stay unhealthy and retain its error: %s", out)
	}
	if strings.Contains(strings.ToLower(got.Error), "firewall") {
		t.Fatalf("a timeout alone does not identify a firewall: %s", out)
	}
}

func TestStatusNamesListenerWithoutCallingItHealthy(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	previous := http.DefaultTransport
	transport := previous.(*http.Transport).Clone()
	transport.DialContext = func(context.Context, string, string) (net.Conn, error) {
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: os.ErrDeadlineExceeded}
	}
	http.DefaultTransport = transport
	t.Cleanup(func() { http.DefaultTransport = previous; transport.CloseIdleConnections() })
	previousHolder := statusPortHolder
	t.Cleanup(func() { statusPortHolder = previousHolder })
	statusPortHolder = func(_ context.Context, port int) (proc.Holder, bool) {
		if port != 43210 {
			t.Fatalf("inspect the requested port, not the default: %d", port)
		}
		return proc.Holder{PID: 1234, Name: "magpie", Path: "/programs/magpie.exe"}, true
	}
	// Neither the stale record's pid nor its version is a gateway reply.
	writeListening(t, "127.0.0.1:3425", 9876)
	for _, args := range [][]string{
		{"status", "--json", "--addr", "127.0.0.1:43210"},
		{"status", "--addr", "127.0.0.1:43210"},
	} {
		out, err := runOut(t, args...)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(out, "9876") {
			t.Fatalf("a stale gateway.json is not evidence of a listener: %s", out)
		}
		if args[1] != "--json" {
			if !strings.Contains(out, "magpie (pid 1234)") || !strings.Contains(out, "firewall or security rules") {
				t.Fatalf("the text status must explain the listener and failed connection: %s", out)
			}
			continue
		}
		var got status
		if err := json.Unmarshal([]byte(out), &got); err != nil {
			t.Fatal(err)
		}
		if got.Running || got.Pid != 0 || got.Version != "" || got.Listener == nil || got.Listener.PID != 1234 || !got.Listener.Magpie {
			t.Fatalf("a local listener does not establish a healthy gateway: %s", out)
		}
		if got.Error == "" || !strings.Contains(got.Hint, "firewall or security rules") {
			t.Fatalf("keep the request error and the possible local causes: %s", out)
		}
	}
}

func TestStatusListenerEvidenceIsLocalAndKnown(t *testing.T) {
	previous := statusPortHolder
	t.Cleanup(func() { statusPortHolder = previous })
	for _, target := range []string{"http://192.0.2.1:3425", "http://example.invalid:3425"} {
		statusPortHolder = func(context.Context, int) (proc.Holder, bool) {
			t.Fatal("a local port holder says nothing about a remote target")
			return proc.Holder{}, false
		}
		if listener, hint := statusListenerAt(target, os.ErrDeadlineExceeded); listener != nil || hint != "" {
			t.Fatalf("remote target got local evidence: %+v %q", listener, hint)
		}
	}
	for _, target := range []string{"http://127.0.0.1:43210", "http://[::1]:43210", "http://localhost:43210"} {
		statusPortHolder = func(context.Context, int) (proc.Holder, bool) {
			return proc.Holder{}, false // no known holder, including an unreadable one
		}
		if listener, hint := statusListenerAt(target, os.ErrDeadlineExceeded); listener != nil || hint != "" {
			t.Fatalf("unknown holder became a diagnosis: %+v %q", listener, hint)
		}
	}
	statusPortHolder = func(context.Context, int) (proc.Holder, bool) {
		return proc.Holder{PID: 1234, Name: "another-server"}, true
	}
	if listener, hint := statusListenerAt("http://127.0.0.1:43210", os.ErrDeadlineExceeded); listener == nil || listener.Magpie || hint != "" {
		t.Fatalf("another program became magpie: %+v %q", listener, hint)
	}
	statusPortHolder = func(context.Context, int) (proc.Holder, bool) {
		return proc.Holder{PID: 1234, Name: "magpie"}, true
	}
	readErr := &net.OpError{Op: "read", Net: "tcp", Err: os.ErrDeadlineExceeded}
	if listener, hint := statusListenerAt("http://127.0.0.1:43210", readErr); listener == nil || !listener.Magpie || strings.Contains(hint, "firewall") || !strings.Contains(hint, "logs") {
		t.Fatalf("an HTTP read timeout is not a failed TCP connection: %+v %q", listener, hint)
	}
	if listener, hint := statusListenerAt("http://127.0.0.1:43210", context.DeadlineExceeded); listener == nil || !strings.Contains(hint, "request timed out") || !strings.Contains(hint, "firewall or security rules") || !strings.Contains(hint, "logs") {
		t.Fatalf("an HTTP client deadline leaves both connection and response failures possible: %+v %q", listener, hint)
	}
}

func TestHealthcheckKeepsFailureAndPointsAtRequestedStatus(t *testing.T) {
	previous := http.DefaultTransport
	transport := previous.(*http.Transport).Clone()
	transport.DialContext = func(context.Context, string, string) (net.Conn, error) {
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: os.ErrDeadlineExceeded}
	}
	http.DefaultTransport = transport
	t.Cleanup(func() { http.DefaultTransport = previous; transport.CloseIdleConnections() })
	previousHolder := statusPortHolder
	statusPortHolder = func(context.Context, int) (proc.Holder, bool) {
		t.Fatal("a watchdog's healthcheck must not wait for a process listing")
		return proc.Holder{}, false
	}
	t.Cleanup(func() { statusPortHolder = previousHolder })
	err := run([]string{"healthcheck", "--addr", "127.0.0.1:43210"})
	if !errors.Is(err, os.ErrDeadlineExceeded) || !strings.Contains(err.Error(), "did not answer") || !strings.Contains(err.Error(), `status --json --addr "127.0.0.1:43210"`) {
		t.Fatalf("keep the failed healthcheck and show how to inspect this address: %v", err)
	}
}
