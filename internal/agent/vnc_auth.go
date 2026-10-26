// File purpose: Issues and consumes one-use credentials for Weston's local PAM authentication.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package agent

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"os"
	"os/user"
	"strconv"
	"strings"
	"time"

	"github.com/RealisLux/NeoDSE/internal/peercred"
	"github.com/RealisLux/NeoDSE/internal/wire"
)

const (
	vncAuthSocketPath = wire.VNCAuthSocketPath
	vncCredentialTTL  = 30 * time.Second
	vncTokenMaxBytes  = wire.MaxVNCTokenBytes
	vncAuthRetryDelay = time.Second
)

type vncCredential struct {
	streamID  string
	token     string
	expiresAt time.Time
}

// startVNCAuthSupervisor keeps the local PAM authority available across
// transient runtime-directory and startup-order failures.
func (a *Agent) startVNCAuthSupervisor(ctx context.Context) {
	err := a.startVNCAuth(ctx)
	if err == nil {
		return
	}
	a.infof("! VNC authentication service unavailable; retrying: %v", err)
	a.workers.Go(func() {
		ticker := time.NewTicker(vncAuthRetryDelay)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := a.startVNCAuth(ctx); err == nil {
					a.infof("| VNC authentication service is ready")
					return
				}
			}
		}
	})
}

// startVNCAuth creates the protected Unix listener and starts its lifecycle workers.
func (a *Agent) startVNCAuth(ctx context.Context) error {
	uiAccount, err := user.Lookup("neodse-ui")
	if err != nil {
		return err
	}
	parsedUID, err := strconv.ParseUint(uiAccount.Uid, 10, 32)
	if err != nil {
		return err
	}
	uiUID := uint32(parsedUID)
	ipcGroup, err := user.LookupGroup("neodse-ipc")
	if err != nil {
		return err
	}
	ipcGID, err := strconv.Atoi(ipcGroup.Gid)
	if err != nil {
		return err
	}
	_ = os.Remove(vncAuthSocketPath)
	listener, err := net.Listen("unix", vncAuthSocketPath)
	if err != nil {
		return err
	}
	if err = os.Chown(vncAuthSocketPath, -1, ipcGID); err == nil {
		err = os.Chmod(vncAuthSocketPath, 0o660) // #nosec G302 -- EXC-VNC-AUTH-SOCKET-GROUP: the authenticated PAM helper requires group access.
	}
	if err != nil {
		_ = listener.Close()
		_ = os.Remove(vncAuthSocketPath)
		return err
	}
	a.vncAuthMu.Lock()
	a.vncCredentials = make(map[[sha256.Size]byte]vncCredential)
	a.vncAuthListener = listener
	a.vncAuthMu.Unlock()
	a.workers.Go(func() {
		<-ctx.Done()
		_ = listener.Close()
		_ = os.Remove(vncAuthSocketPath)
	})
	a.workers.Go(func() { a.serveVNCAuth(listener, uiUID) })
	return nil
}

// serveVNCAuth serializes short authentication requests on the local authority socket.
func (a *Agent) serveVNCAuth(listener net.Listener, allowedUID uint32) {
	for {
		connection, err := listener.Accept()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				a.verbosef("! VNC authentication socket: %v", err)
			}
			return
		}
		a.handleVNCAuthConnection(connection, allowedUID)
	}
}

// handleVNCAuthConnection validates the peer UID and consumes at most one token.
func (a *Agent) handleVNCAuthConnection(connection net.Conn, allowedUID uint32) {
	defer connection.Close()
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok || peercred.UID(unixConnection) != allowedUID {
		return
	}
	_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
	reader := bufio.NewReaderSize(io.LimitReader(connection, vncTokenMaxBytes+2), vncTokenMaxBytes+2)
	token, err := reader.ReadString('\n')
	if err != nil || len(token) > vncTokenMaxBytes+1 {
		return
	}
	token = strings.TrimSuffix(token, "\n")
	if a.consumeVNCCredential(token) {
		_, _ = connection.Write([]byte{1})
		return
	}
	_, _ = connection.Write([]byte{0})
}

// prepareVNCCredential creates one expiring capability bound to a display stream.
func (a *Agent) prepareVNCCredential(streamID string) (string, error) {
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(random)
	hash := sha256.Sum256([]byte(token))
	now := time.Now().UTC()
	a.vncAuthMu.Lock()
	if a.vncAuthListener == nil {
		a.vncAuthMu.Unlock()
		return "", errors.New("VNC authentication service is not ready")
	}
	if a.vncCredentials == nil {
		a.vncCredentials = make(map[[sha256.Size]byte]vncCredential)
	}
	for key, credential := range a.vncCredentials {
		if !credential.expiresAt.After(now) {
			delete(a.vncCredentials, key)
		}
	}
	if len(a.vncCredentials) >= 64 {
		a.vncAuthMu.Unlock()
		return "", errors.New("VNC credential capacity reached")
	}
	a.vncCredentials[hash] = vncCredential{streamID: streamID, token: token, expiresAt: now.Add(vncCredentialTTL)}
	a.vncAuthMu.Unlock()
	return token, nil
}

// vncCredentialForStream retrieves a live capability for the matching prepared stream.
func (a *Agent) vncCredentialForStream(streamID string) (string, bool) {
	now := time.Now().UTC()
	a.vncAuthMu.Lock()
	defer a.vncAuthMu.Unlock()
	for _, credential := range a.vncCredentials {
		if credential.streamID == streamID && credential.expiresAt.After(now) {
			return credential.token, true
		}
	}
	return "", false
}

// consumeVNCCredential invalidates a capability before checking its stream binding.
func (a *Agent) consumeVNCCredential(token string) bool {
	if len(token) < wire.MinVNCTokenBytes || len(token) > vncTokenMaxBytes {
		return false
	}
	hash := sha256.Sum256([]byte(token))
	now := time.Now().UTC()
	a.vncAuthMu.Lock()
	credential, exists := a.vncCredentials[hash]
	delete(a.vncCredentials, hash)
	a.vncAuthMu.Unlock()
	if !exists || credential.streamID == "" || !credential.expiresAt.After(now) {
		return false
	}
	a.displayMu.Lock()
	streamOpen := a.displayStreams[credential.streamID] != nil
	a.displayMu.Unlock()
	return streamOpen
}

// revokeVNCCredentials invalidates every outstanding capability for a stream.
func (a *Agent) revokeVNCCredentials(streamID string) {
	a.vncAuthMu.Lock()
	for hash, credential := range a.vncCredentials {
		if credential.streamID == streamID {
			delete(a.vncCredentials, hash)
		}
	}
	a.vncAuthMu.Unlock()
}
