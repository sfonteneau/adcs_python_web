/* Swagger UI loader. Local files are preferred; CDN is a pinned fallback.
   Production: `python3 scripts/vendor_swagger_ui.py` to remove runtime CDN dependency.
   Tokens are deliberately NOT persisted or passed to any query string. */
(() => {
  'use strict';
  const CDN_BASE = 'https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.32.0/';
  const LOCAL_BASE = '/api/docs/assets/';
  const loading = document.getElementById('loading');
  const error = document.getElementById('error');

  function asset(kind, name, src) {
    return new Promise((resolve, reject) => {
      const element = document.createElement(kind === 'css' ? 'link' : 'script');
      if (kind === 'css') {
        element.rel = 'stylesheet';
        element.href = src;
      } else {
        element.src = src;
        element.async = true;
      }
      element.onload = resolve;
      element.onerror = () => {
        element.remove();
        reject(new Error('Impossible de charger ' + name));
      };
      document.head.appendChild(element);
    });
  }

  async function load(name, kind) {
    try {
      await asset(kind, name, LOCAL_BASE + name);
    } catch (_) {
      await asset(kind, name, CDN_BASE + name);
    }
  }

  async function start() {
    try {
      await Promise.all([
        load('swagger-ui.css', 'css'),
        load('swagger-ui-bundle.js', 'js'),
      ]);
      if (typeof window.SwaggerUIBundle !== 'function') {
        throw new Error('Swagger UI could not be initialized.');
      }
      window.ui = window.SwaggerUIBundle({
        url: '/api/openapi.json',
        dom_id: '#swagger-ui',
        deepLinking: true,
        docExpansion: 'list',
        displayRequestDuration: true,
        filter: true,
        validatorUrl: null,
        persistAuthorization: false,
        presets: [window.SwaggerUIBundle.presets.apis],
      });
      loading.hidden = true;
    } catch (exc) {
      loading.hidden = true;
      error.hidden = false;
      error.textContent = 'Impossible de charger Swagger UI. ' + exc.message +
        ' For isolated networks, install local assets using python3 scripts/vendor_swagger_ui.py ' +
        ' (documentation OpenAPI disponible dans /api/openapi.json).';
    }
  }

  start();
})();
