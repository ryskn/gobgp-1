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
	"bytes"
	"errors"
	"fmt"
	"maps"
	"math"
	"net/netip"
	"slices"
	"sync"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/internal/pkg/netutils"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type tcpAoKeychain struct {
	mu   sync.RWMutex
	name string
	keys map[uint8]netutils.TCPAOKey
}

type tcpAoKeychainStore struct {
	// keychains must only be accessed from mgmtOperation callbacks while shared.mu is held.
	keychains map[string]*tcpAoKeychain
}

func newTcpAoKeychainStore() *tcpAoKeychainStore {
	return &tcpAoKeychainStore{keychains: make(map[string]*tcpAoKeychain)}
}

func (s *tcpAoKeychainStore) addKeychain(chain *tcpAoKeychain) {
	s.keychains[chain.name] = chain
}

func (s *tcpAoKeychainStore) getKeychain(name string) (*tcpAoKeychain, bool) {
	chain, ok := s.keychains[name]
	return chain, ok
}

func (s *tcpAoKeychainStore) getAllKeychains() []*tcpAoKeychain {
	return slices.Collect(maps.Values(s.keychains))
}

func (s *tcpAoKeychainStore) deleteKeychain(name string) bool {
	chain, ok := s.keychains[name]
	if !ok {
		return false
	}
	chain.clearKeys()
	delete(s.keychains, name)
	return true
}

func (s *tcpAoKeychainStore) clearAllKeychains() {
	for _, chain := range s.keychains {
		chain.clearKeys()
	}
	clear(s.keychains)
}

func newTcpAoKeychain(a *api.TcpAoKeychain) (*tcpAoKeychain, error) {
	keys, err := newTcpAoKeys(a.Name, a.Keys)
	if err != nil {
		return nil, err
	}
	if err := netutils.ValidateTCPAOKeys(keys); err != nil {
		clearTcpAoKeys(keys)
		return nil, status.Errorf(codes.InvalidArgument, "TCP-AO keychain %q: %v", a.Name, err)
	}
	keyMap := make(map[uint8]netutils.TCPAOKey, len(keys))
	for _, key := range keys {
		keyMap[key.SendID] = key
	}
	return &tcpAoKeychain{name: a.Name, keys: keyMap}, nil
}

// newTcpAoKeys converts API keys and validates each key on its own. Checks that
// span the whole key set, such as the key count and duplicate IDs, are left to
// the caller. An update must validate the merged key set, not just the keys it
// adds.
func newTcpAoKeys(chainName string, keys []*api.TcpAoKey) ([]netutils.TCPAOKey, error) {
	result := make([]netutils.TCPAOKey, 0, len(keys))
	for i, key := range keys {
		converted, err := newTcpAoKey(chainName, i, key)
		if err != nil {
			clearTcpAoKeys(result)
			return nil, err
		}
		result = append(result, converted)
	}
	return result, nil
}

// newTcpAoKey converts one API key that carries keying material. Requests that
// only identify a key, such as the delete list of an update, use tcpAoKeyIDs.
func newTcpAoKey(chainName string, index int, key *api.TcpAoKey) (netutils.TCPAOKey, error) {
	sendID, receiveID, err := tcpAoKeyIDs(chainName, index, key)
	if err != nil {
		return netutils.TCPAOKey{}, err
	}
	algorithm, ok := tcpAoAlgorithm(key.Algorithm)
	if !ok {
		return netutils.TCPAOKey{}, status.Errorf(codes.InvalidArgument, "TCP-AO keychain %q key at index %d has unsupported algorithm %s", chainName, index, key.Algorithm)
	}
	return netutils.TCPAOKey{
		SendID:            sendID,
		ReceiveID:         receiveID,
		Algorithm:         algorithm,
		ExcludeTCPOptions: key.ExcludeTcpOptions,
		MasterKey:         bytes.Clone(key.MasterKey),
	}, nil
}

// tcpAoKeyIDs converts the key IDs of one API key. RFC 5925 carries the KeyID in
// a single byte, so a value above 255 cannot be represented. The API uses uint32
// because proto3 has no 8-bit integer type.
func tcpAoKeyIDs(chainName string, index int, key *api.TcpAoKey) (uint8, uint8, error) {
	if key == nil {
		return 0, 0, status.Errorf(codes.InvalidArgument, "TCP-AO keychain %q key at index %d is nil", chainName, index)
	}
	if key.SendId > math.MaxUint8 {
		return 0, 0, status.Errorf(codes.InvalidArgument, "TCP-AO keychain %q key at index %d has send ID %d outside 0..255", chainName, index, key.SendId)
	}
	if key.ReceiveId > math.MaxUint8 {
		return 0, 0, status.Errorf(codes.InvalidArgument, "TCP-AO keychain %q key at index %d has receive ID %d outside 0..255", chainName, index, key.ReceiveId)
	}
	return uint8(key.SendId), uint8(key.ReceiveId), nil
}

// tcpAoAlgorithm maps an API algorithm to the netutils one. The two enums are
// mapped explicitly so that they can be changed independently.
func tcpAoAlgorithm(algorithm api.TcpAoAlgorithm) (netutils.TCPAOAlgorithm, bool) {
	switch algorithm {
	case api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA1_96:
		return netutils.TCPAOAlgorithmHMACSHA1, true
	case api.TcpAoAlgorithm_TCP_AO_ALGORITHM_AES_128_CMAC_96:
		return netutils.TCPAOAlgorithmAES128CMAC, true
	default:
		return netutils.TCPAOAlgorithmUnspecified, false
	}
}

func apiTcpAoAlgorithm(algorithm netutils.TCPAOAlgorithm) api.TcpAoAlgorithm {
	switch algorithm {
	case netutils.TCPAOAlgorithmHMACSHA1:
		return api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA1_96
	case netutils.TCPAOAlgorithmAES128CMAC:
		return api.TcpAoAlgorithm_TCP_AO_ALGORITHM_AES_128_CMAC_96
	default:
		return api.TcpAoAlgorithm_TCP_AO_ALGORITHM_UNSPECIFIED
	}
}

// validateTcpAoKeychainUpdate converts the keys of an update request and checks
// the result against the current contents of the keychain. It returns the keys
// to add and the keys to delete.
func validateTcpAoKeychainUpdate(keychain *tcpAoKeychain, request *api.UpdateTcpAoKeychainRequest) ([]netutils.TCPAOKey, []netutils.TCPAOKey, error) {
	var deleted []netutils.TCPAOKey
	seen := make(map[uint8]struct{}, len(request.DeleteKeys))
	for i, delKey := range request.DeleteKeys {
		sendID, receiveID, err := tcpAoKeyIDs(request.Name, i, delKey)
		if err != nil {
			return nil, nil, err
		}
		if _, duplicate := seen[sendID]; duplicate {
			return nil, nil, status.Errorf(codes.InvalidArgument, "TCP-AO keychain %q delete request contains duplicate send ID %d", request.Name, sendID)
		}
		key, exists := keychain.getKey(sendID, receiveID)
		if !exists {
			return nil, nil, status.Errorf(codes.NotFound, "TCP-AO keychain %q does not contain key with send ID %d and receive ID %d", request.Name, sendID, receiveID)
		}
		seen[sendID] = struct{}{}
		deleted = append(deleted, key)
	}

	added, err := newTcpAoKeys(request.Name, request.AddKeys)
	if err != nil {
		return nil, nil, err
	}
	if err := netutils.ValidateTCPAOKeys(keychain.mergedKeys(added, deleted)); err != nil {
		clearTcpAoKeys(added)
		return nil, nil, status.Errorf(codes.InvalidArgument, "TCP-AO keychain %q: %v", request.Name, err)
	}
	return added, deleted, nil
}

// clearTcpAoKeys zeroes the master key of every key. Only call it for keys that
// no keychain holds, because the master key storage is shared with the keychain.
func clearTcpAoKeys(keys []netutils.TCPAOKey) {
	for _, key := range keys {
		clear(key.MasterKey)
	}
}

func (c *tcpAoKeychain) toAPIKeychain() *api.TcpAoKeychain {
	c.mu.RLock()
	defer c.mu.RUnlock()

	result := &api.TcpAoKeychain{
		Name: c.name,
		Keys: make([]*api.TcpAoKey, 0, len(c.keys)),
	}
	sendIDs := make([]uint8, 0, len(c.keys))
	for sendID := range c.keys {
		sendIDs = append(sendIDs, sendID)
	}
	slices.Sort(sendIDs)
	for _, sendID := range sendIDs {
		key := c.keys[sendID]
		result.Keys = append(result.Keys, &api.TcpAoKey{
			SendId:            uint32(key.SendID),
			ReceiveId:         uint32(key.ReceiveID),
			Algorithm:         apiTcpAoAlgorithm(key.Algorithm),
			ExcludeTcpOptions: key.ExcludeTCPOptions,
			// MasterKey is intentionally omitted
		})
	}
	return result
}

// socketConfig returns the keys of the keychain in the form the socket helpers
// expect. The master keys are copied so that a concurrent keychain update
// cannot zero them while a socket operation is in flight. The caller must
// release the copy with clearTcpAoKeys.
//
// preferredSendID selects the key the socket signs with. It must be nil for a
// listening socket, which has no current key: an accepted connection signs with
// the key that the peer requested in RNextKey.
func (c *tcpAoKeychain) socketConfig(preferredSendID *uint8) netutils.TCPAOConfig {
	c.mu.RLock()
	defer c.mu.RUnlock()

	config := netutils.TCPAOConfig{
		Keys:            make([]netutils.TCPAOKey, 0, len(c.keys)),
		PreferredSendID: preferredSendID,
	}
	for _, sendID := range slices.Sorted(maps.Keys(c.keys)) {
		key := c.keys[sendID]
		key.MasterKey = bytes.Clone(key.MasterKey)
		config.Keys = append(config.Keys, key)
	}
	return config
}

func (c *tcpAoKeychain) hasSendID(sendID uint8) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	_, ok := c.keys[sendID]
	return ok
}

func (c *tcpAoKeychain) getKey(sendID, receiveID uint8) (netutils.TCPAOKey, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	key, ok := c.keys[sendID]
	if !ok || key.ReceiveID != receiveID {
		return netutils.TCPAOKey{}, false
	}
	return key, true
}

// mergedKeys returns the key set the keychain would hold once the given keys are
// deleted and added. The returned keys share master key storage with the
// keychain, so the caller must not clear them.
func (c *tcpAoKeychain) mergedKeys(added, deleted []netutils.TCPAOKey) []netutils.TCPAOKey {
	c.mu.RLock()
	defer c.mu.RUnlock()

	remaining := maps.Clone(c.keys)
	for _, key := range deleted {
		delete(remaining, key.SendID)
	}
	merged := slices.Collect(maps.Values(remaining))
	return append(merged, added...)
}

func (c *tcpAoKeychain) updateKeys(added, deleted []netutils.TCPAOKey) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, deletedKey := range deleted {
		key, ok := c.keys[deletedKey.SendID]
		if !ok || key.ReceiveID != deletedKey.ReceiveID {
			continue
		}
		clear(key.MasterKey)
		delete(c.keys, deletedKey.SendID)
	}
	for _, key := range added {
		c.keys[key.SendID] = key
	}
}

func (c *tcpAoKeychain) clearKeys() {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, key := range c.keys {
		clear(key.MasterKey)
	}
	clear(c.keys)
}

// tcpAoPeerScope returns the TCP-AO key scope of one peer address. The kernel
// selects keys by prefix, so a single peer becomes a host prefix. The IPv6 zone
// of an unnumbered peer is dropped because a key scope cannot carry one.
func tcpAoPeerScope(addr netip.Addr) netip.Prefix {
	unzoned := addr.Unmap().WithZone("")
	return netip.PrefixFrom(unzoned, unzoned.BitLen())
}

// resolveTcpAoKeychain looks up the keychain that a peer or a peer-group
// references. TCP-AO is enabled by referencing a keychain, so an empty
// reference resolves to no keychain.
//
// The reference is resolved when the configuration is accepted rather than when
// the session is established, so that a keychain name or a send ID that does
// not exist is reported to the caller that configured it.
func resolveTcpAoKeychain(store *tcpAoKeychainStore, config *oc.TcpAoConfig, authPassword string) (*tcpAoKeychain, error) {
	if config.Keychain == "" {
		return nil, nil
	}
	if authPassword != "" {
		// TCP-AO obsoletes the TCP MD5 signature option (RFC 5925, section 1)
		// and Linux rejects both options on the same socket.
		return nil, fmt.Errorf("TCP-AO and TCP MD5 authentication are mutually exclusive")
	}
	keychain, ok := store.getKeychain(string(config.Keychain))
	if !ok {
		return nil, fmt.Errorf("TCP-AO keychain %q does not exist", config.Keychain)
	}
	if !keychain.hasSendID(config.PreferredSendId) {
		return nil, fmt.Errorf("TCP-AO keychain %q does not contain a key with send ID %d", config.Keychain, config.PreferredSendId)
	}
	return keychain, nil
}

// attachTcpAoListenerKeys installs the keys of a peer on the shared BGP
// listening sockets. Linux authenticates the SYN of an incoming connection
// against the listening socket and copies the matching keys to the accepted
// socket, so the keys have to be installed before the peer connects. The keys
// are scoped to the peer, which lets one listener carry the keys of every peer.
func (s *BgpServer) attachTcpAoListenerKeys(scope netip.Prefix, bindInterface string, keychain *tcpAoKeychain) error {
	config := keychain.socketConfig(nil)
	defer clearTcpAoKeys(config.Keys)

	for _, l := range s.listListeners(scope.Addr().String()) {
		sc, err := l.SyscallConn()
		if err == nil {
			err = netutils.AddTCPAOKeysSockopt(sc, scope, bindInterface, config)
		}
		if err != nil {
			// Do not leave a listener holding a part of the key set behind.
			// Removing a key that was never installed fails, so the result of
			// the rollback carries no information.
			_ = s.deleteTcpAoListenerKeys(scope, bindInterface, config)
			return err
		}
	}
	return nil
}

// detachTcpAoListenerKeys removes the keys of a peer from the shared BGP
// listening sockets. Connections that are already established keep their own
// copy of the keys, so this only stops new connections from being accepted.
func (s *BgpServer) detachTcpAoListenerKeys(scope netip.Prefix, bindInterface string, keychain *tcpAoKeychain) error {
	config := keychain.socketConfig(nil)
	defer clearTcpAoKeys(config.Keys)

	return s.deleteTcpAoListenerKeys(scope, bindInterface, config)
}

func (s *BgpServer) deleteTcpAoListenerKeys(scope netip.Prefix, bindInterface string, config netutils.TCPAOConfig) error {
	var errs []error
	for _, l := range s.listListeners(scope.Addr().String()) {
		sc, err := l.SyscallConn()
		if err == nil {
			err = netutils.DeleteTCPAOKeysSockopt(sc, scope, bindInterface, config)
		}
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// tcpAoKeychainUser returns the name of a peer or peer-group that references the
// given keychain. Removing a keychain zeroes its master keys, so a keychain that
// is still referenced must not be removed.
func (s *BgpServer) tcpAoKeychainUser(name string) string {
	for addr, peer := range s.neighborMap {
		if string(peer.fsm.pConf.ReadOnly().TcpAo.Config.Keychain) == name {
			return fmt.Sprintf("neighbor %s", addr)
		}
	}
	for pgName, pg := range s.peerGroupMap {
		if string(pg.Conf.TcpAo.Config.Keychain) == name {
			return fmt.Sprintf("peer-group %s", pgName)
		}
	}
	return ""
}
