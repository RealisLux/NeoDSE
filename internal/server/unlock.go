// File purpose: Keeps the controller locked until root supplies the database passphrase, and manages that passphrase.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package server

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"time"
	"unicode"

	"github.com/RealisLux/NeoDSE/internal/config"
	"github.com/RealisLux/NeoDSE/internal/peercred"
	"github.com/RealisLux/NeoDSE/internal/provisioning"
	"github.com/RealisLux/NeoDSE/internal/store"
	"github.com/RealisLux/NeoDSE/internal/storekey"
)

const (
	// unlockSocketPath lives in the RuntimeDirectory of neodse-server.service.
	unlockSocketPath = "/run/neodse-server/unlock.sock"
	// unlockRequestTimeout bounds how long a connected client may take to send its passphrase.
	unlockRequestTimeout = 10 * time.Second
	// unlockStartupTimeout bounds key derivation, database opening and recovery for one attempt.
	unlockStartupTimeout = time.Minute
	unlockResponseBytes  = 1024
	passphrasePrompt     = "Controller database passphrase: "
)

var errControllerNotLocked = errors.New("the controller is not waiting to be unlocked; check systemctl status neodse-server")

// readKeyslot loads the bounded keyslot of a database without following symlinks.
func readKeyslot(databasePath string) ([]byte, error) {
	path := storekey.Path(databasePath)
	contents, err := provisioning.ReadBoundedFile(path, storekey.MaxFileBytes)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("database keyslot %s is missing; the controller database cannot be unlocked", path)
	}
	if err != nil {
		return nil, fmt.Errorf("read database keyslot %s: %w", path, err)
	}
	return contents, nil
}

// writeKeyslotFile publishes a keyslot owned by the controller service account.
func writeKeyslotFile(path string, contents []byte) error {
	return provisioning.WriteServiceFile(path, contents, 0o600, "neodse-server", "neodse-server")
}

// readNewDatabasePassphrase reads and validates a passphrase chosen by the administrator.
func readNewDatabasePassphrase(ctx context.Context, input *os.File, output io.Writer) ([]byte, error) {
	passphrase, err := provisioning.ReadNewPassphrase(ctx, input, output, "New database passphrase: ", storekey.MaxPassphraseBytes)
	if err != nil {
		return nil, err
	}
	if err := storekey.ValidatePassphrase(passphrase); err != nil {
		clear(passphrase)
		return nil, err
	}
	return passphrase, nil
}

// unsealDatabaseKey prompts for the passphrase and returns the configured database key.
func unsealDatabaseKey(ctx context.Context, databasePath string, input *os.File, output io.Writer) ([]byte, error) {
	keyslot, err := readKeyslot(databasePath)
	if err != nil {
		return nil, err
	}
	passphrase, err := provisioning.ReadPassphrase(ctx, input, output, passphrasePrompt, storekey.MaxPassphraseBytes)
	if err != nil {
		return nil, err
	}
	defer clear(passphrase)
	return storekey.Unseal(keyslot, passphrase)
}

// openMaintenanceDatabase opens the database for a one-shot root command after
// the administrator enters its passphrase.
func (s *Server) openMaintenanceDatabase(ctx context.Context, input *os.File, output io.Writer) error {
	key, err := unsealDatabaseKey(ctx, s.config.Server.Database, input, output)
	if err != nil {
		return err
	}
	defer clear(key)
	return s.openDatabase(key)
}

// waitForUnlock keeps the controller locked until root sends the database
// passphrase over the unlock socket, then opens and prepares the database.
// It returns the context error when the service stops while still locked.
func (s *Server) waitForUnlock(ctx context.Context, socketPath string, allowedUID uint32) error {
	if _, err := readKeyslot(s.config.Server.Database); err != nil {
		return err
	}
	if _, err := os.Lstat(s.config.Server.Database); err != nil {
		return fmt.Errorf("controller database %s: %w", s.config.Server.Database, err)
	}
	listener, err := listenUnlockSocket(socketPath)
	if err != nil {
		return fmt.Errorf("unlock socket: %w", err)
	}
	defer listener.Close()
	stop := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer stop()
	log.Printf("> Controller database is locked; run neodse-server unlock as root to start the controller")
	for {
		connection, err := listener.Accept()
		if err != nil {
			if contextErr := ctx.Err(); contextErr != nil {
				return contextErr
			}
			return fmt.Errorf("unlock socket: %w", err)
		}
		unlocked, err := s.handleUnlock(connection, allowedUID)
		if err != nil || unlocked {
			return err
		}
	}
}

// listenUnlockSocket replaces a stale socket and restricts the new one to its
// owner. Closing the listener removes the socket file.
func listenUnlockSocket(path string) (*net.UnixListener, error) {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("%s exists and is not a socket", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = listener.Close()
		return nil, err
	}
	return listener, nil
}

// handleUnlock serves one request. A wrong passphrase leaves the controller
// locked; once the key is correct, any failure to start is returned so the
// service exits and systemd starts it again in the locked state.
func (s *Server) handleUnlock(connection net.Conn, allowedUID uint32) (bool, error) {
	defer connection.Close()
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok || peercred.UID(unixConnection) != allowedUID {
		log.Printf("! Database unlock rejected: the caller is not root")
		return false, nil
	}
	_ = connection.SetDeadline(time.Now().Add(unlockRequestTimeout))
	passphrase, err := readUnlockRequest(connection)
	if err != nil {
		writeUnlockResponse(connection, "error invalid unlock request")
		return false, nil
	}
	defer clear(passphrase)
	_ = connection.SetDeadline(time.Now().Add(unlockStartupTimeout))
	keyslot, err := readKeyslot(s.config.Server.Database)
	if err != nil {
		writeUnlockResponse(connection, "error "+err.Error())
		return false, err
	}
	key, err := storekey.Unseal(keyslot, passphrase)
	if errors.Is(err, storekey.ErrIncorrectPassphrase) {
		log.Printf("! Database unlock rejected: incorrect passphrase")
		writeUnlockResponse(connection, "error "+err.Error())
		return false, nil
	}
	if err != nil {
		writeUnlockResponse(connection, "error "+err.Error())
		return false, err
	}
	defer clear(key)
	if err := s.openUnlockedDatabase(key); err != nil {
		writeUnlockResponse(connection, "error controller startup failed: "+err.Error())
		return false, err
	}
	writeUnlockResponse(connection, "ok")
	log.Printf("> Controller database unlocked")
	return true, nil
}

// openUnlockedDatabase opens the store and recovers interrupted deliveries before serving.
func (s *Server) openUnlockedDatabase(key []byte) error {
	if err := s.openDatabase(key); err != nil {
		return fmt.Errorf("open controller database: %w", err)
	}
	recoveryContext, stopRecovery := boundedStoreContext()
	err := s.store.RecoverDeliveries(recoveryContext)
	stopRecovery()
	if err != nil {
		_ = s.store.Close()
		s.store = nil
		return fmt.Errorf("recover controller deliveries: %w", err)
	}
	return nil
}

// readUnlockRequest reads one newline-terminated passphrase from a client.
func readUnlockRequest(connection io.Reader) ([]byte, error) {
	reader := bufio.NewReaderSize(io.LimitReader(connection, storekey.MaxPassphraseBytes+1), storekey.MaxPassphraseBytes+1)
	line, err := reader.ReadSlice('\n')
	defer clear(line)
	if err != nil || len(line) < 2 {
		return nil, errors.New("invalid unlock request")
	}
	return bytes.Clone(line[:len(line)-1]), nil
}

// writeUnlockResponse sends one line without control characters.
func writeUnlockResponse(connection io.Writer, response string) {
	response = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, response)
	if len(response) > unlockResponseBytes-1 {
		response = response[:unlockResponseBytes-1]
	}
	_, _ = io.WriteString(connection, response+"\n")
}

// unlockController implements neodse-server unlock.
func unlockController(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("unlock", flag.ContinueOnError)
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unlock accepts no positional arguments")
	}
	return requestUnlock(ctx, unlockSocketPath, os.Stdin, os.Stderr)
}

// requestUnlock sends the passphrase to a locked controller and reports its answer.
func requestUnlock(ctx context.Context, socketPath string, input *os.File, output io.Writer) error {
	if info, err := os.Lstat(socketPath); err != nil || info.Mode()&os.ModeSocket == 0 {
		return errControllerNotLocked
	}
	passphrase, err := provisioning.ReadPassphrase(ctx, input, output, passphrasePrompt, storekey.MaxPassphraseBytes)
	if err != nil {
		return err
	}
	defer clear(passphrase)
	request := append(passphrase, '\n')
	defer clear(request)
	dialer := net.Dialer{Timeout: 5 * time.Second}
	connection, err := dialer.DialContext(ctx, "unix", socketPath)
	if err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return contextErr
		}
		return errControllerNotLocked
	}
	defer connection.Close()
	stop := context.AfterFunc(ctx, func() { _ = connection.SetDeadline(time.Now()) })
	defer stop()
	_ = connection.SetDeadline(time.Now().Add(unlockRequestTimeout + unlockStartupTimeout))
	if _, err := connection.Write(request); err != nil {
		return fmt.Errorf("send unlock request: %w", err)
	}
	response, err := bufio.NewReader(io.LimitReader(connection, unlockResponseBytes)).ReadString('\n')
	if contextErr := ctx.Err(); contextErr != nil {
		return contextErr
	}
	if err != nil {
		return errors.New("the controller closed the unlock connection; check journalctl -u neodse-server")
	}
	response = strings.TrimSuffix(response, "\n")
	if response == "ok" {
		fmt.Fprintln(output, "> Controller database unlocked; the controller is starting.")
		return nil
	}
	if message, found := strings.CutPrefix(response, "error "); found {
		return fmt.Errorf("unlock failed: %s", message)
	}
	return errors.New("unexpected unlock response")
}

// changeDatabasePassphrase implements neodse-server change-passphrase.
func changeDatabasePassphrase(ctx context.Context, args []string) error {
	configPath := config.DefaultServerPath
	flags := flag.NewFlagSet("change-passphrase", flag.ContinueOnError)
	flags.StringVar(&configPath, "config", configPath, "server configuration path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("change-passphrase accepts no positional arguments")
	}
	loaded, err := config.LoadServer(configPath)
	if err != nil {
		return err
	}
	if err := rewrapKeyslot(ctx, loaded.Server.Database, os.Stdin, os.Stderr, writeKeyslotFile); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "> Database passphrase changed. Earlier keyslot backups still open with the old passphrase.")
	return nil
}

// rewrapKeyslot seals the unchanged database key under a new passphrase.
func rewrapKeyslot(ctx context.Context, databasePath string, input *os.File, output io.Writer, write func(string, []byte) error) error {
	key, err := unsealDatabaseKey(ctx, databasePath, input, output)
	if err != nil {
		return err
	}
	defer clear(key)
	passphrase, err := readNewDatabasePassphrase(ctx, input, output)
	if err != nil {
		return err
	}
	defer clear(passphrase)
	sealed, err := storekey.Seal(key, passphrase)
	if err != nil {
		return err
	}
	return write(storekey.Path(databasePath), sealed)
}

// The keyslot and the store must agree on the key length; a difference fails compilation.
var _ = [1]struct{}{}[store.KeySize-storekey.KeySize]
