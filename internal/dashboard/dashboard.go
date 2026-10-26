// File purpose: Serves the NeoDSE operator dashboard without external assets.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

// Package dashboard embeds the browser-based NeoDSE operator console.
package dashboard

import (
	"embed"
	"net/http"

	"github.com/RealisLux/NeoDSE/internal/brand"
)

const dashboardContentSecurityPolicy = "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"

//go:embed index.html
var indexHTML []byte

//go:embed app.js api.js events.js display.js
var scripts embed.FS

// RegisterRoutes installs the dashboard at the server root. Authentication is
// performed by the API calls issued from the page, so opening the page itself
// never exposes control data.
func RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/dashboard/logo.png", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		_, _ = w.Write(brand.LogoPNG)
	})
	for _, name := range []string{"app.js", "api.js", "events.js", "display.js"} {
		source, err := scripts.ReadFile(name)
		if err != nil {
			// The go:embed directive above lists every name, so this is a build defect.
			panic(err)
		}
		mux.HandleFunc("/dashboard/"+name, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			_, _ = w.Write(source)
		})
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		// Live JPEG frames are decoded into a canvas without object URLs.
		w.Header().Set("Content-Security-Policy", dashboardContentSecurityPolicy)
		_, _ = w.Write(indexHTML)
	})
}
