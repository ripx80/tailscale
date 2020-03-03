// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package magicsock

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"tailscale.com/stun"
)

func TestListen(t *testing.T) {
	epCh := make(chan string, 16)
	epFunc := func(endpoints []string) {
		for _, ep := range endpoints {
			epCh <- ep
		}
	}

	stunAddr := serveSTUN(t)

	port := pickPort(t)
	conn, err := Listen(Options{
		Port:          port,
		STUN:          []string{stunAddr.String()},
		EndpointsFunc: epFunc,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	go func() {
		var pkt [64 << 10]byte
		for {
			_, _, _, err := conn.ReceiveIPv4(pkt[:])
			if err != nil {
				return
			}
		}
	}()

	timeout := time.After(10 * time.Second)
	var endpoints []string
	suffix := fmt.Sprintf(":%d", port)
collectEndpoints:
	for {
		select {
		case ep := <-epCh:
			endpoints = append(endpoints, ep)
			if strings.HasSuffix(ep, suffix) {
				break collectEndpoints
			}
		case <-timeout:
			t.Fatalf("timeout with endpoints: %v", endpoints)
		}
	}
}

func pickPort(t *testing.T) uint16 {
	t.Helper()
	conn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	return uint16(conn.LocalAddr().(*net.UDPAddr).Port)
}

func TestDerpIPConstant(t *testing.T) {
	if derpMagicIPStr != derpMagicIP.String() {
		t.Errorf("str %q != IP %v", derpMagicIPStr, derpMagicIP)
	}
}

type stunStats struct {
	mu       sync.Mutex
	readIPv4 int
	readIPv6 int
}

func serveSTUN(t *testing.T) net.Addr {
	t.Helper()

	// TODO(crawshaw): use stats to test re-STUN logic
	var stats stunStats

	pc, err := net.ListenPacket("udp4", ":3478")
	if err != nil {
		t.Fatalf("failed to open STUN listener: %v", err)
	}
	t.Cleanup(func() { pc.Close() })

	go runSTUN(pc, &stats)
	return pc.LocalAddr()
}

func runSTUN(pc net.PacketConn, stats *stunStats) {
	var buf [64 << 10]byte
	for {
		n, addr, err := pc.ReadFrom(buf[:])
		if err != nil {
			continue
		}
		ua, ok := addr.(*net.UDPAddr)
		if !ok {
			continue
		}
		pkt := buf[:n]
		if !stun.Is(pkt) {
			continue
		}
		txid, err := stun.ParseBindingRequest(pkt)
		if err != nil {
			continue
		}

		stats.mu.Lock()
		if ua.IP.To4() != nil {
			stats.readIPv4++
		} else {
			stats.readIPv6++
		}
		stats.mu.Unlock()

		res := stun.Response(txid, ua.IP, uint16(ua.Port))
		_, err = pc.WriteTo(res, addr)
	}
}
