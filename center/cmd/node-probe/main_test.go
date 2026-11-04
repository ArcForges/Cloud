// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestTheFlagsAreChecked: a center URL of another shape, an unknown flow or decision, a case name a file name could misuse are refused.
func TestTheFlagsAreChecked(t *testing.T) {
	good := []string{"-center", "https://proof.arcforges.com/api", "-flow", "pkce", "-dir", t.TempDir(), "-case", "pkce-1"}
	if _, err := parse(good, io.Discard); err != nil {
		t.Fatal(err)
	}
	for _, change := range [][2]string{{"-center", "http://proof.arcforges.com/api"}, {"-center", "https://proof.arcforges.com/api/"},
		{"-center", "https://user@proof.arcforges.com/api"}, {"-center", "https://proof.arcforges.com/api?x"}, {"-flow", "token"},
		{"-case", "../x"}, {"-case", "A"}, {"-decision", "maybe"}, {"-poll-floor", "10ms"}} {
		args := append([]string(nil), good...)
		for index := range args {
			if args[index] == change[0] {
				args[index+1] = change[1]
			}
		}
		if change[0] == "-decision" || change[0] == "-poll-floor" {
			args = append(args, change[0], change[1])
		}
		if _, err := parse(args, io.Discard); err == nil {
			t.Errorf("%v was accepted", change)
		}
	}
	local := []string{"-center", "http://localhost:18080", "-flow", "device", "-dir", t.TempDir(), "-case", "d"}
	if _, err := parse(local, io.Discard); err != nil {
		t.Fatal(err)
	}
}

// TestTheReceiverTakesOneValidResult: the loopback receiver answers 400 to a foreign host, another path or method, another state and an
// extra key, and returns the first valid request.
func TestTheReceiverTakesOneValidResult(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	host := listener.Addr().String()
	state := strings.Repeat("s", 43)
	got := make(chan string, 1)
	go func() {
		redirect, receiveErr := receive(listener, state, time.Minute)
		if receiveErr != nil {
			got <- "error: " + receiveErr.Error()
			return
		}
		got <- redirect
	}()
	client := &http.Client{Timeout: 5 * time.Second}
	send := func(method, path, hostHeader string) int {
		request, requestErr := http.NewRequest(method, "http://"+host+path, nil)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		request.Host = hostHeader
		for attempt := 0; ; attempt++ {
			reply, sendErr := client.Do(request)
			if sendErr == nil {
				_ = reply.Body.Close()
				return reply.StatusCode
			}
			if attempt > 20 {
				t.Fatal(sendErr)
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	code := strings.Repeat("c", 43)
	for _, probe := range []struct{ method, path, host string }{
		{http.MethodGet, "/callback?code=" + code + "&state=" + state, "localhost:" + strings.Split(host, ":")[1]},
		{http.MethodGet, "/other?code=" + code + "&state=" + state, host},
		{http.MethodPost, "/callback?code=" + code + "&state=" + state, host},
		{http.MethodGet, "/callback?code=" + code + "&state=other", host},
		{http.MethodGet, "/callback?code=" + code + "&state=" + state + "&x=1", host},
		{http.MethodGet, "/callback?code=" + code + "&code=" + code + "&state=" + state, host},
	} {
		if status := send(probe.method, probe.path, probe.host); status != http.StatusBadRequest {
			t.Errorf("%s %s (%s): %d", probe.method, probe.path, probe.host, status)
		}
	}
	if status := send(http.MethodGet, "/callback?code="+code+"&state="+state, host); status != http.StatusOK {
		t.Fatalf("the valid result: %d", status)
	}
	if redirect := <-got; redirect != fmt.Sprintf("http://%s/callback?code=%s&state=%s", host, code, state) {
		t.Fatalf("the receiver returned %q", redirect)
	}
}
