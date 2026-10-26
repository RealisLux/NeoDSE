// File purpose: Owns API handler admission and joins in-flight work before storage closes.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package server

import "net/http"

// ownHTTP prevents shutdown races from starting untracked storage operations.
func (s *Server) ownHTTP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.httpMu.Lock()
		if s.httpClosing {
			s.httpMu.Unlock()
			http.Error(w, "controller stopping", http.StatusServiceUnavailable)
			return
		}
		s.httpWorkers.Add(1)
		s.httpMu.Unlock()
		defer s.httpWorkers.Done()
		next.ServeHTTP(w, r)
	})
}

// stopHTTPAdmission prevents new handlers from acquiring storage ownership.
func (s *Server) stopHTTPAdmission() {
	s.httpMu.Lock()
	s.httpClosing = true
	s.httpMu.Unlock()
}
