// File purpose: Serves pinned offline Swagger assets and the authoritative OpenAPI contract.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

// Package swagger embeds and serves NeoDSE's OpenAPI specification and
// vendored Swagger UI without runtime filesystem or network dependencies.
package swagger

import (
	_ "embed"
	"net/http"
)

//go:embed openapi.yaml
var openAPISpec []byte

//go:embed index.html
var swaggerHTML []byte

//go:embed swagger-init.js
var swaggerInitJS []byte

//go:embed vendor/swagger-ui.css
var swaggerCSS []byte

//go:embed vendor/swagger-ui-bundle.js
var swaggerBundleJS []byte

//go:embed vendor/LICENSE
var swaggerLicense []byte

//go:embed vendor/swagger-ui-bundle.js.LICENSE.txt
var swaggerBundleNotices []byte

//go:embed vendor/THIRD-PARTY-NOTICES
var swaggerSupplementalNotices []byte

// RegisterRoutes adds the embedded API specification and offline Swagger UI
// endpoints to mux.
func RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/docs", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w)
			return
		}
		http.Redirect(w, r, "/docs/", http.StatusTemporaryRedirect)
	})
	mux.HandleFunc("/docs/", swaggerUIHandler)
	mux.HandleFunc("/openapi.yaml", openAPIHandler)
}

// swaggerUIHandler serves only pinned local documentation assets with strict methods.
func swaggerUIHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}

	switch r.URL.Path {
	case "/docs/":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; connect-src 'self'; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline'; script-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
		_, _ = w.Write(swaggerHTML)
	case "/docs/swagger-init.js":
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(swaggerInitJS)
	case "/docs/swagger-ui.css":
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		_, _ = w.Write(swaggerCSS)
	case "/docs/swagger-ui-bundle.js":
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		_, _ = w.Write(swaggerBundleJS)
	case "/docs/swagger-ui-bundle.js.LICENSE.txt":
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		_, _ = w.Write(swaggerLicense)
		_, _ = w.Write([]byte("\n\n"))
		_, _ = w.Write(swaggerBundleNotices)
		_, _ = w.Write([]byte("\n\n"))
		_, _ = w.Write(swaggerSupplementalNotices)
	default:
		http.NotFound(w, r)
	}
}

// openAPIHandler serves the embedded contract without cache or remote validation.
func openAPIHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w)
		return
	}

	w.Header().Set("Content-Type", "application/vnd.oai.openapi;version=3.0.3")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(openAPISpec)
}

// writeMethodNotAllowed rejects a method with the Allow header that RFC 9110 requires.
func writeMethodNotAllowed(w http.ResponseWriter) {
	w.Header().Set("Allow", http.MethodGet)
	w.WriteHeader(http.StatusMethodNotAllowed)
}
