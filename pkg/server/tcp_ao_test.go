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

package server

import (
	"context"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/internal/pkg/netutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

func testTcpAoKeychain(name string) *api.TcpAoKeychain {
	return &api.TcpAoKeychain{
		Name: name,
		Keys: []*api.TcpAoKey{{
			SendId:            1,
			ReceiveId:         2,
			Algorithm:         api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA1_96,
			ExcludeTcpOptions: true,
			MasterKey:         []byte("secret"),
		}},
	}
}

func TestTcpAoKeychainValidation(t *testing.T) {
	s := NewBgpServer()
	go s.Serve()
	t.Cleanup(func() {
		require.NoError(t, s.StopBgp(context.Background(), &api.StopBgpRequest{}))
	})
	add := func(keychain *api.TcpAoKeychain) error {
		return s.AddTcpAoKeychain(context.Background(), &api.AddTcpAoKeychainRequest{Keychain: keychain})
	}
	update := func(request *api.UpdateTcpAoKeychainRequest) error {
		_, err := s.UpdateTcpAoKeychain(context.Background(), request)
		return err
	}

	// The update cases below all fail, so none of them changes this keychain.
	require.NoError(t, add(&api.TcpAoKeychain{
		Name: "update-chain",
		Keys: []*api.TcpAoKey{
			{SendId: 5, ReceiveId: 15, Algorithm: api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA1_96, MasterKey: []byte("five")},
			{SendId: 9, ReceiveId: 19, Algorithm: api.TcpAoAlgorithm_TCP_AO_ALGORITHM_AES_128_CMAC_96, MasterKey: []byte("nine")},
		},
	}))

	tests := []struct {
		name string
		fn   func() error
		code codes.Code
	}{
		{
			name: "missing keychain",
			fn:   func() error { return add(nil) },
			code: codes.InvalidArgument,
		},
		{
			name: "missing name",
			fn:   func() error { return add(testTcpAoKeychain("")) },
			code: codes.InvalidArgument,
		},
		{
			name: "no keys",
			fn:   func() error { return add(&api.TcpAoKeychain{Name: "chain"}) },
			code: codes.InvalidArgument,
		},
		{
			name: "nil key",
			fn:   func() error { return add(&api.TcpAoKeychain{Name: "chain", Keys: []*api.TcpAoKey{nil}}) },
			code: codes.InvalidArgument,
		},
		{
			name: "send ID overflow",
			fn: func() error {
				return add(&api.TcpAoKeychain{Name: "chain", Keys: []*api.TcpAoKey{{SendId: 256, Algorithm: api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA1_96, MasterKey: []byte{1}}}})
			},
			code: codes.InvalidArgument,
		},
		{
			name: "receive ID overflow",
			fn: func() error {
				return add(&api.TcpAoKeychain{Name: "chain", Keys: []*api.TcpAoKey{{ReceiveId: 256, Algorithm: api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA1_96, MasterKey: []byte{1}}}})
			},
			code: codes.InvalidArgument,
		},
		{
			name: "duplicate send ID",
			fn: func() error {
				return add(&api.TcpAoKeychain{Name: "chain", Keys: []*api.TcpAoKey{
					{SendId: 1, ReceiveId: 1, Algorithm: api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA1_96, MasterKey: []byte{1}},
					{SendId: 1, ReceiveId: 2, Algorithm: api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA1_96, MasterKey: []byte{2}},
				}})
			},
			code: codes.InvalidArgument,
		},
		{
			name: "duplicate receive ID",
			fn: func() error {
				return add(&api.TcpAoKeychain{Name: "chain", Keys: []*api.TcpAoKey{
					{SendId: 1, ReceiveId: 1, Algorithm: api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA1_96, MasterKey: []byte{1}},
					{SendId: 2, ReceiveId: 1, Algorithm: api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA1_96, MasterKey: []byte{2}},
				}})
			},
			code: codes.InvalidArgument,
		},
		{
			name: "unspecified algorithm",
			fn: func() error {
				return add(&api.TcpAoKeychain{Name: "chain", Keys: []*api.TcpAoKey{{MasterKey: []byte{1}}}})
			},
			code: codes.InvalidArgument,
		},
		{
			name: "unknown algorithm",
			fn: func() error {
				return add(&api.TcpAoKeychain{Name: "chain", Keys: []*api.TcpAoKey{{Algorithm: api.TcpAoAlgorithm(99), MasterKey: []byte{1}}}})
			},
			code: codes.InvalidArgument,
		},
		{
			name: "empty master key",
			fn: func() error {
				return add(&api.TcpAoKeychain{Name: "chain", Keys: []*api.TcpAoKey{{Algorithm: api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA1_96}}})
			},
			code: codes.InvalidArgument,
		},
		{
			name: "long master key",
			fn: func() error {
				return add(&api.TcpAoKeychain{Name: "chain", Keys: []*api.TcpAoKey{{Algorithm: api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA1_96, MasterKey: make([]byte, netutils.TCPAOMaxKeyLen+1)}}})
			},
			code: codes.InvalidArgument,
		},
		{
			name: "nil update request",
			fn:   func() error { return update(nil) },
			code: codes.InvalidArgument,
		},
		{
			name: "missing update name",
			fn:   func() error { return update(&api.UpdateTcpAoKeychainRequest{}) },
			code: codes.InvalidArgument,
		},
		{
			name: "nil delete request",
			fn:   func() error { return s.DeleteTcpAoKeychain(context.Background(), nil) },
			code: codes.InvalidArgument,
		},
		{
			name: "missing delete name",
			fn: func() error {
				return s.DeleteTcpAoKeychain(context.Background(), &api.DeleteTcpAoKeychainRequest{})
			},
			code: codes.InvalidArgument,
		},
		{
			name: "nil list request",
			fn: func() error {
				return s.ListTcpAoKeychain(context.Background(), nil, func(*api.TcpAoKeychain) {})
			},
			code: codes.InvalidArgument,
		},
		{
			name: "nil list callback",
			fn: func() error {
				return s.ListTcpAoKeychain(context.Background(), &api.ListTcpAoKeychainRequest{}, nil)
			},
			code: codes.InvalidArgument,
		},
		{
			name: "delete missing key",
			fn: func() error {
				return update(&api.UpdateTcpAoKeychainRequest{Name: "update-chain", DeleteKeys: []*api.TcpAoKey{{SendId: 5, ReceiveId: 99}}})
			},
			code: codes.NotFound,
		},
		{
			name: "delete key twice",
			fn: func() error {
				return update(&api.UpdateTcpAoKeychainRequest{Name: "update-chain", DeleteKeys: []*api.TcpAoKey{
					{SendId: 5, ReceiveId: 15},
					{SendId: 5, ReceiveId: 15},
				}})
			},
			code: codes.InvalidArgument,
		},
		{
			name: "add duplicate send ID",
			fn: func() error {
				return update(&api.UpdateTcpAoKeychainRequest{Name: "update-chain", AddKeys: []*api.TcpAoKey{{
					SendId: 9, ReceiveId: 29, Algorithm: api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA1_96, MasterKey: []byte("duplicate"),
				}}})
			},
			code: codes.InvalidArgument,
		},
		{
			name: "add duplicate receive ID",
			fn: func() error {
				return update(&api.UpdateTcpAoKeychainRequest{Name: "update-chain", AddKeys: []*api.TcpAoKey{{
					SendId: 29, ReceiveId: 19, Algorithm: api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA1_96, MasterKey: []byte("duplicate"),
				}}})
			},
			code: codes.InvalidArgument,
		},
		{
			name: "add send ID overflow",
			fn: func() error {
				return update(&api.UpdateTcpAoKeychainRequest{Name: "update-chain", AddKeys: []*api.TcpAoKey{{
					SendId: 256, ReceiveId: 29, Algorithm: api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA1_96, MasterKey: []byte("overflow"),
				}}})
			},
			code: codes.InvalidArgument,
		},
		{
			name: "add receive ID overflow",
			fn: func() error {
				return update(&api.UpdateTcpAoKeychainRequest{Name: "update-chain", AddKeys: []*api.TcpAoKey{{
					SendId: 29, ReceiveId: 256, Algorithm: api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA1_96, MasterKey: []byte("overflow"),
				}}})
			},
			code: codes.InvalidArgument,
		},
		{
			name: "delete every key",
			fn: func() error {
				return update(&api.UpdateTcpAoKeychainRequest{Name: "update-chain", DeleteKeys: []*api.TcpAoKey{
					{SendId: 5, ReceiveId: 15},
					{SendId: 9, ReceiveId: 19},
				}})
			},
			code: codes.InvalidArgument,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.code, status.Code(tt.fn()))
		})
	}
}

func TestTcpAoKeychainOperations(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "gobgp.sock")
	socketAddr := "unix://" + socketPath
	s := NewBgpServer(GrpcListenAddress(socketAddr))
	go s.Serve()
	t.Cleanup(s.Stop)
	require.Eventually(t, func() bool {
		_, err := os.Stat(socketPath)
		return err == nil
	}, time.Second, 10*time.Millisecond)

	conn, err := grpc.NewClient(socketAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, conn.Close()) })
	client := api.NewGoBgpServiceClient(conn)

	_, err = client.AddTcpAoKeychain(context.Background(), &api.AddTcpAoKeychainRequest{
		Keychain: testTcpAoKeychain("chain"),
	})
	require.NoError(t, err)

	updated, err := client.UpdateTcpAoKeychain(context.Background(), &api.UpdateTcpAoKeychainRequest{
		Name: "chain",
		DeleteKeys: []*api.TcpAoKey{{
			SendId:    1,
			ReceiveId: 2,
		}},
		AddKeys: []*api.TcpAoKey{{
			SendId: 1, ReceiveId: 2, Algorithm: api.TcpAoAlgorithm_TCP_AO_ALGORITHM_AES_128_CMAC_96, MasterKey: []byte("replacement"),
		}},
	})
	require.NoError(t, err)
	require.NotNil(t, updated.Keychain)
	require.Len(t, updated.Keychain.Keys, 1)
	assert.Equal(t, uint32(1), updated.Keychain.Keys[0].SendId)
	assert.Equal(t, uint32(2), updated.Keychain.Keys[0].ReceiveId)
	assert.Equal(t, api.TcpAoAlgorithm_TCP_AO_ALGORITHM_AES_128_CMAC_96, updated.Keychain.Keys[0].Algorithm)
	assert.Empty(t, updated.Keychain.Keys[0].MasterKey)

	stream, err := client.ListTcpAoKeychain(context.Background(), &api.ListTcpAoKeychainRequest{Name: "chain"})
	require.NoError(t, err)
	listed, err := stream.Recv()
	require.NoError(t, err)
	assert.True(t, proto.Equal(updated.Keychain, listed.Keychain),
		"listed %v, updated %v", listed.Keychain, updated.Keychain)
	_, err = stream.Recv()
	assert.ErrorIs(t, err, io.EOF)

	_, err = client.DeleteTcpAoKeychain(context.Background(), &api.DeleteTcpAoKeychainRequest{Name: "chain"})
	require.NoError(t, err)
	// Name is a filter, so listing a keychain that does not exist yields no
	// entries rather than an error.
	stream, err = client.ListTcpAoKeychain(context.Background(), &api.ListTcpAoKeychainRequest{Name: "chain"})
	require.NoError(t, err)
	_, err = stream.Recv()
	assert.ErrorIs(t, err, io.EOF)
}

func TestTcpAoPeerScope(t *testing.T) {
	tests := []struct {
		addr string
		want string
	}{
		{addr: "10.0.0.1", want: "10.0.0.1/32"},
		{addr: "2001:db8::1", want: "2001:db8::1/128"},
		// A TCP-AO scope carries neither an IPv6 zone nor a mapped IPv4 address.
		{addr: "fe80::1%eth0", want: "fe80::1/128"},
		{addr: "::ffff:10.0.0.1", want: "10.0.0.1/32"},
	}
	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			assert.Equal(t, tt.want, tcpAoPeerScope(netip.MustParseAddr(tt.addr)).String())
		})
	}
}

// newTcpAoTestServer starts a server without a listening socket, so that the
// tests below exercise the configuration path on every platform. Installing
// keys on a socket needs TCP-AO support from the kernel.
func newTcpAoTestServer(t *testing.T) *BgpServer {
	t.Helper()
	s := NewBgpServer()
	go s.Serve()
	t.Cleanup(func() {
		require.NoError(t, s.StopBgp(context.Background(), &api.StopBgpRequest{}))
	})
	require.NoError(t, s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        65001,
			RouterId:   "1.1.1.1",
			ListenPort: -1,
		},
	}))
	require.NoError(t, s.AddTcpAoKeychain(context.Background(), &api.AddTcpAoKeychainRequest{
		Keychain: testTcpAoKeychain("chain"),
	}))
	return s
}

func tcpAoTestPeer(address string, tcpAo *api.TcpAoPeerConfig) *api.Peer {
	return &api.Peer{
		Conf: &api.PeerConf{
			NeighborAddress: address,
			PeerAsn:         65002,
			AdminDown:       true,
		},
		TcpAo: tcpAo,
	}
}

// peerTcpAoKeychain returns the keychain the FSM of a peer authenticates with.
// The neighbor map is only safe to read from a management operation.
func peerTcpAoKeychain(t *testing.T, s *BgpServer, address string) *tcpAoKeychain {
	t.Helper()
	var keychain *tcpAoKeychain
	err := s.mgmtOperation(func() error {
		peer, ok := s.neighborMap[netip.MustParseAddr(address)]
		if !ok {
			return fmt.Errorf("no such peer: %s", address)
		}
		keychain = peer.fsm.tcpAoKeychain
		return nil
	}, false)
	require.NoError(t, err)
	return keychain
}

func TestTcpAoPeerConfigRejected(t *testing.T) {
	s := newTcpAoTestServer(t)

	md5AndTcpAo := tcpAoTestPeer("10.0.0.4", &api.TcpAoPeerConfig{Keychain: "chain", PreferredSendId: 1})
	md5AndTcpAo.Conf.AuthPassword = "password"

	tests := []struct {
		name string
		peer *api.Peer
		err  string
	}{
		{
			name: "unknown keychain",
			peer: tcpAoTestPeer("10.0.0.1", &api.TcpAoPeerConfig{Keychain: "missing", PreferredSendId: 1}),
			err:  `TCP-AO keychain "missing" does not exist`,
		},
		{
			name: "send ID not in keychain",
			peer: tcpAoTestPeer("10.0.0.2", &api.TcpAoPeerConfig{Keychain: "chain", PreferredSendId: 7}),
			err:  `TCP-AO keychain "chain" does not contain a key with send ID 7`,
		},
		{
			name: "send ID out of range",
			peer: tcpAoTestPeer("10.0.0.3", &api.TcpAoPeerConfig{Keychain: "chain", PreferredSendId: 256}),
			err:  "TCP-AO preferred send ID 256 is outside 0..255",
		},
		{
			name: "md5 and TCP-AO",
			peer: md5AndTcpAo,
			err:  "TCP-AO and TCP MD5 authentication are mutually exclusive",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.ErrorContains(t, s.AddPeer(context.Background(), &api.AddPeerRequest{Peer: tt.peer}), tt.err)
			// The peer must not be configured when its keys cannot be resolved.
			assert.Error(t, s.DeletePeer(context.Background(), &api.DeletePeerRequest{
				Address: tt.peer.Conf.NeighborAddress,
			}))
		})
	}
}

func TestTcpAoPeerConfigAccepted(t *testing.T) {
	s := newTcpAoTestServer(t)

	peer := tcpAoTestPeer("10.0.0.1", &api.TcpAoPeerConfig{Keychain: "chain", PreferredSendId: 1})
	require.NoError(t, s.AddPeer(context.Background(), &api.AddPeerRequest{Peer: peer}))
	keychain := peerTcpAoKeychain(t, s, "10.0.0.1")
	require.NotNil(t, keychain)
	assert.Equal(t, "chain", keychain.name)

	// A keychain that a peer references cannot be removed, its master keys are
	// still needed by the peer.
	err := s.DeleteTcpAoKeychain(context.Background(), &api.DeleteTcpAoKeychainRequest{Name: "chain"})
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))

	// An update that cannot be resolved leaves the peer untouched.
	peer.TcpAo.PreferredSendId = 7
	_, err = s.UpdatePeer(context.Background(), &api.UpdatePeerRequest{Peer: peer})
	require.Error(t, err)
	assert.Same(t, keychain, peerTcpAoKeychain(t, s, "10.0.0.1"))

	require.NoError(t, s.DeletePeer(context.Background(), &api.DeletePeerRequest{Address: "10.0.0.1"}))
	require.NoError(t, s.DeleteTcpAoKeychain(context.Background(), &api.DeleteTcpAoKeychainRequest{Name: "chain"}))
}

func TestTcpAoPeerGroupInheritance(t *testing.T) {
	s := newTcpAoTestServer(t)

	require.NoError(t, s.AddPeerGroup(context.Background(), &api.AddPeerGroupRequest{
		PeerGroup: &api.PeerGroup{
			Conf:  &api.PeerGroupConf{PeerGroupName: "group", PeerAsn: 65002},
			TcpAo: &api.TcpAoPeerConfig{Keychain: "chain", PreferredSendId: 1},
		},
	}))

	// The neighbor does not configure TCP-AO itself, it inherits the keychain
	// of its peer-group.
	peer := tcpAoTestPeer("10.0.0.1", nil)
	peer.Conf.PeerGroup = "group"
	require.NoError(t, s.AddPeer(context.Background(), &api.AddPeerRequest{Peer: peer}))

	keychain := peerTcpAoKeychain(t, s, "10.0.0.1")
	require.NotNil(t, keychain)
	assert.Equal(t, "chain", keychain.name)

	err := s.DeleteTcpAoKeychain(context.Background(), &api.DeleteTcpAoKeychainRequest{Name: "chain"})
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
}
