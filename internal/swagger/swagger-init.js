// NeoDSE - embedded Swagger UI initialization.
// Copyright (c) 2026 RealisLux. SPDX-License-Identifier: MIT. Project: https://github.com/RealisLux/NeoDSE.
window.ui = SwaggerUIBundle({
  url: "/openapi.yaml",
  dom_id: "#swagger-ui",
  deepLinking: true,
  validatorUrl: null,
  persistAuthorization: false,
  displayRequestDuration: true,
});
