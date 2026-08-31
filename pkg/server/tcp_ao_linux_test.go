// Copyright (C) 2026 The GoBGP Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build linux

package server

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/internal/pkg/netutils"
	"github.com/stretchr/testify/require"
)

// requireTcpAoSupport skips the test unless the kernel accepts TCP-AO keys.
// TCP-AO needs Linux 6.7 or newer built with CONFIG_TCP_AO.
func requireTcpAoSupport(t *testing.T) {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer l.Close()

	sc, err := l.(*net.TCPListener).SyscallConn()
	require.NoError(t, err)
	err = netutils.AddTCPAOKeysSockopt(sc, netip.MustParsePrefix("127.0.0.2/32"), "", netutils.TCPAOConfig{
		Keys: []netutils.TCPAOKey{{
			SendID:    1,
			ReceiveID: 1,
			Algorithm: netutils.TCPAOAlgorithmHMACSHA1,
			MasterKey: []byte("tcp-ao-probe"),
		}},
	})
	if err != nil {
		t.Skipf("kernel does not support TCP-AO: %v", err)
	}
}

// tcpAoTestKeychain builds a keychain with a single key. RFC 5925 numbers the
// two directions of a connection separately: the KeyID of a segment is the
// SendID of the sender and has to match the ReceiveID of the receiver, so the
// two ends of a session use mirrored IDs and the same master key.
func tcpAoTestKeychain(name string, sendID, receiveID uint32, masterKey string) *api.TcpAoKeychain {
	return &api.TcpAoKeychain{
		Name: name,
		Keys: []*api.TcpAoKey{{
			SendId:    sendID,
			ReceiveId: receiveID,
			Algorithm: api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA1_96,
			MasterKey: []byte(masterKey),
		}},
	}
}

// startTcpAoTestServer starts a server that authenticates its only peer, which
// is reachable over the loopback interface, with TCP-AO.
func startTcpAoTestServer(t *testing.T, asn uint32, routerID string, listenPort, remotePort int32, keychain *api.TcpAoKeychain, sendID uint32) *BgpServer {
	t.Helper()
	s := NewBgpServer()
	go s.Serve()
	t.Cleanup(func() {
		require.NoError(t, s.StopBgp(context.Background(), &api.StopBgpRequest{}))
	})
	require.NoError(t, s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        asn,
			RouterId:   routerID,
			ListenPort: listenPort,
		},
	}))
	require.NoError(t, s.AddTcpAoKeychain(context.Background(), &api.AddTcpAoKeychainRequest{
		Keychain: keychain,
	}))

	peer := &api.Peer{
		Conf: &api.PeerConf{
			NeighborAddress: "127.0.0.1",
			PeerAsn:         asn ^ 3,
		},
		Transport: &api.Transport{
			// The server without a listening socket is the one that connects.
			PassiveMode: remotePort == 0,
			RemotePort:  uint32(remotePort),
		},
		Timers: &api.Timers{
			Config: &api.TimersConfig{
				ConnectRetry:           1,
				IdleHoldTimeAfterReset: 1,
			},
		},
		TcpAo: &api.TcpAoPeerConfig{
			Keychain:        keychain.Name,
			PreferredSendId: sendID,
		},
	}
	require.NoError(t, s.AddPeer(context.Background(), &api.AddPeerRequest{Peer: peer}))
	return s
}

// TestTcpAoSessionEstablishment checks both ends of the wiring: the passive
// server authenticates the incoming connection with the keys installed on its
// listening socket, the active server signs the outgoing connection with the
// keys installed on its socket before connect.
func TestTcpAoSessionEstablishment(t *testing.T) {
	requireTcpAoSupport(t)

	const listenPort = 10379
	passive := startTcpAoTestServer(t, 1, "1.1.1.1", listenPort, 0, tcpAoTestKeychain("chain", 2, 1, "shared-master-key"), 2)
	active := startTcpAoTestServer(t, 2, "2.2.2.2", -1, listenPort, tcpAoTestKeychain("chain", 1, 2, "shared-master-key"), 1)

	waitPeerState(t, passive, api.PeerState_SESSION_STATE_ESTABLISHED, 30*time.Second)
	waitPeerState(t, active, api.PeerState_SESSION_STATE_ESTABLISHED, 30*time.Second)
}

// TestTcpAoSessionKeyMismatch checks that TCP-AO is enforced: a peer whose
// master key differs must not be able to establish a session.
func TestTcpAoSessionKeyMismatch(t *testing.T) {
	requireTcpAoSupport(t)

	const listenPort = 10380
	passive := startTcpAoTestServer(t, 1, "1.1.1.1", listenPort, 0, tcpAoTestKeychain("chain", 2, 1, "master-key-of-the-passive-side"), 2)
	startTcpAoTestServer(t, 2, "2.2.2.2", -1, listenPort, tcpAoTestKeychain("chain", 1, 2, "master-key-of-the-active-side"), 1)

	w := newPeerStateWaiter(passive, api.PeerState_SESSION_STATE_ESTABLISHED)
	defer w.cancel()
	select {
	case <-w.doneCh:
		t.Fatal("session was established even though the master keys differ")
	case <-time.After(5 * time.Second):
	}
}
