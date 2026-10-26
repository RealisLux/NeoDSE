// File purpose: Loads root-controlled VNC trust for certificate-verified loopback TLS.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package agent

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

const vncCertificatePath = "/var/lib/neodse-vnc/server.crt"

// loadVNCTLSConfig refuses mutable or substituted trust files before any credential is sent.
func loadVNCTLSConfig(path string) (*tls.Config, error) {
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	parentOwner, ok := parent.Sys().(*syscall.Stat_t)
	if !ok || !parent.IsDir() || parentOwner.Uid != 0 || parent.Mode().Perm()&0o022 != 0 {
		return nil, errors.New("VNC trust directory must be root-owned and not group/world writable")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	information, err := file.Stat()
	if err != nil {
		return nil, err
	}
	owner, ok := information.Sys().(*syscall.Stat_t)
	if !ok || !information.Mode().IsRegular() || owner.Uid != 0 || information.Mode().Perm()&0o022 != 0 {
		return nil, errors.New("VNC trust file must be regular, root-owned and not group/world writable")
	}
	contents, err := io.ReadAll(io.LimitReader(file, 16385))
	if err != nil {
		return nil, err
	}
	if len(contents) > 16384 {
		return nil, errors.New("VNC trust certificate exceeds 16 KiB")
	}
	return vncTLSConfig(contents)
}

// vncTLSConfig trusts only the provisioned certificate, never the system CA pool.
func vncTLSConfig(contents []byte) (*tls.Config, error) {
	contents = bytes.TrimSpace(contents)
	if !bytes.HasPrefix(contents, []byte("-----BEGIN CERTIFICATE-----")) {
		return nil, errors.New("VNC trust must start with a PEM certificate")
	}
	block, rest := pem.Decode(contents)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("VNC trust must contain exactly one PEM certificate")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	return &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: "127.0.0.1"}, nil
}
