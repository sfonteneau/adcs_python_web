/* ADCS Console: pure browser JavaScript. No framework, build step or embedded credentials.
   All ADCS operations are performed by the separately deployed authenticated JSON API. */
(() => {
  'use strict';

  const CONFIG = window.ADCS_WEB_CONFIG || {};
  const DEFAULT_API_BASE = String(CONFIG.apiBaseUrl || '/api/v1');
  const STORAGE_SERVER_KEY = 'adcs_server_url';
  let apiBase = DEFAULT_API_BASE;
  function normalizeApiBase(value) {
    const raw = String(value || '').trim().replace(/\/+$/, '');
    if (!raw) throw new Error('Renseignez une adresse de serveur ADCS.');
    // Allow same-origin reverse proxy setups as well as remote API URLs.
    if (raw.startsWith('/')) {
      if (raw.startsWith('//') || !raw.startsWith('/api/')) throw new Error('Invalid API path.');
      return raw;
    }
    let url;
    try { url = new URL(raw); } catch (_error) { throw new Error('Adresse API invalide.'); }
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.search || url.hash || !url.hostname) {
      throw new Error('Use an HTTP(S) URL without credentials, query parameters or fragments.');
    }
    if (!url.pathname.endsWith('/api/v1')) {
      // An origin-only value is convenient when typing an IP and port.
      if (url.pathname === '/' || url.pathname === '') url.pathname = '/api/v1';
      else throw new Error('The URL must end with /api/v1.');
    }
    return url.href.replace(/\/+$/, '');
  }
  function selectedApiBase() { return normalizeApiBase($('loginServer').value); }
  async function useServer() {
    const next = selectedApiBase();
    if (state.token && apiBase !== next) throw new Error('Sign out before changing servers.');
    apiBase = next;
    return next;
  }
  const $ = (id) => document.getElementById(id);
  const state = {
    token: null, username: '', cas: [], ca: '', rows: [], total: 0,
    selected: new Set(), focused: null, sortKey: 'not_before', sortDirection: 'ASC',
    queryVersion: 0, detailVersion: 0, busy: false, filters: {status: 'any', revocation: 'any', search: '', limit: 1000},
  };
  const fmtNumber = (value) => new Intl.NumberFormat('fr-FR').format(Number(value || 0));
  const labelForCA = (ca) => ca ? (ca.display_name || ca.id) : '';
  const pathForCA = () => '/cas/' + encodeURIComponent(state.ca);

  function notify(message, kind = '') {
    const box = document.createElement('div');
    box.className = 'toast ' + kind;
    box.textContent = message;
    box.setAttribute('role', kind === 'error' ? 'alert' : 'status');
    $('toastArea').appendChild(box);
    setTimeout(() => box.remove(), 5900);
  }
  function showLogin(message = '') {
    state.token = null;
    state.username = '';
    state.ca = '';
    state.rows = [];
    state.selected.clear();
    $('appView').hidden = true;
    $('loginView').hidden = false;
    $('loginError').hidden = !message;
    $('loginError').textContent = message;
    $('loginPassword').value = '';
    $('loginPassword').focus();
    if ($('dialog').open) $('dialog').close();
  }
  async function api(method, path, data = undefined) {
    const headers = { Accept: 'application/json' };
    if (data !== undefined) headers['Content-Type'] = 'application/json';
    if (state.token) headers.Authorization = 'Bearer ' + state.token;
    let response;
    try {
      response = await fetch(apiBase + path, {
        method, headers, body: data === undefined ? undefined : JSON.stringify(data),
        cache: 'no-store', credentials: 'omit', redirect: 'error',
      });
    } catch (_error) {
      throw new Error('Cannot reach the ADCS API. Check the URL, TLS and proxy settings.');
    }
    const result = await response.json().catch(() => null);
    if (!response.ok) {
      const message = result?.error?.message || `API HTTP error ${response.status}`;
      if (response.status === 401 && path !== '/auth/login' && state.token) {
        showLogin('Session expired. Please sign in again.');
      }
      throw new Error(message);
    }
    if (!result || !Object.prototype.hasOwnProperty.call(result, 'data')) {
      throw new Error('Unexpected API response format (JSON required).');
    }
    return result.data;
  }
  async function healthCheck() {
    try {
      await useServer();
      const result = await api('GET', '/health');
      $('loginDot').className = 'status-dot ' + (result.status === 'ok' ? 'online' : 'offline');
      $('loginConnection').textContent = result.status === 'ok' ? 'API disponible' : 'API non disponible';
    } catch (_error) {
      $('loginDot').className = 'status-dot offline';
      $('loginConnection').textContent = 'API unavailable · check URL and CORS';
    }
  }
  async function login(event) {
    event.preventDefault();
    const button = $('loginButton');
    button.disabled = true;
    $('loginError').hidden = true;
    try {
      await useServer();
      const response = await api('POST', '/auth/login', {
        username: $('loginUser').value.trim(), password: $('loginPassword').value,
      });
      state.token = response.access_token; // In memory ONLY; never localStorage/cookies.
      try { localStorage.setItem(STORAGE_SERVER_KEY, apiBase); } catch (_error) { /* optional */ }
      state.username = response.username;
      $('userLabel').textContent = response.username;
      $('loginPassword').value = '';
      $('loginView').hidden = true;
      $('appView').hidden = false;
      await loadCAs();
      notify('Signed in successfully.', 'success');
    } catch (error) {
      $('loginError').textContent = error.message;
      $('loginError').hidden = false;
    } finally {
      button.disabled = false;
    }
  }
  async function logout() {
    try { if (state.token) await api('POST', '/auth/logout', {}); }
    catch (_error) { /* Local token must be cleared even if the network is down. */ }
    showLogin();
    notify('Signed out.');
  }

  async function loadCAs(preferred = state.ca) {
    const cas = await api('GET', '/cas');
    if (!Array.isArray(cas)) throw new Error('Invalid authority list.');
    state.cas = cas;
    const select = $('caSelect');
    select.replaceChildren();
    if (!cas.length) {
      select.add(new Option('No CA configured', ''));
      await selectCA('');
      return;
    }
    cas.forEach((ca) => select.add(new Option(labelForCA(ca) + '  [' + ca.id + ']', ca.id)));
    const next = cas.some((ca) => ca.id === preferred) ? preferred : cas[0].id;
    select.value = next;
    await selectCA(next);
  }
  async function selectCA(ca) {
    state.ca = ca;
    state.focused = null;
    state.selected.clear();
    state.rows = [];
    state.total = 0;
    ++state.queryVersion;
    ++state.detailVersion;
    const current = state.cas.find((item) => item.id === ca);
    $('breadcrumbCA').textContent = current ? labelForCA(current) : 'Certificats';
    $('pageSubtitle').textContent = current ? `${current.id} · Certificates issued by this authority` : 'No certificate authority available.';
    resetDetail();
    updateCounts();
    drawTable();
    closeSidebar();
    if (ca) await loadCertificates();
  }
  function syncFilters() {
    state.filters = {
      search: $('searchInput').value.trim(),
      status: $('statusFilter').value,
      revocation: $('revocationFilter').value,
      limit: Number($('maxRows').value),
    };
    if (!Number.isInteger(state.filters.limit) || state.filters.limit < 0 || state.filters.limit > 50000) {
      state.filters.limit = 1000;
      $('maxRows').value = '1000';
    }
  }
  const orderBy = () => `${state.sortKey} ${state.sortDirection}`;
  async function loadCertificates() {
    if (!state.ca) return;
    syncFilters();
    const sequence = ++state.queryVersion;
    const ca = state.ca;
    state.busy = true;
    $('tableDescription').textContent = 'Loading certificates…';
    const query = new URLSearchParams({
      status: state.filters.status,
      revocation: state.filters.revocation,
      search: state.filters.search,
      order_by: orderBy(),
      limit: String(state.filters.limit),
    });
    try {
      const payload = await api('GET', pathForCA() + '/certificates?' + query);
      if (sequence !== state.queryVersion || ca !== state.ca) return;
      state.rows = payload.certificates || [];
      state.total = payload.total ?? state.rows.length;
      const visible = new Set(state.rows.map((row) => row.serial));
      for (const serial of state.selected) if (!visible.has(serial)) state.selected.delete(serial);
      if (state.focused && !visible.has(state.focused)) {
        state.focused = null;
        resetDetail();
      }
      drawTable();
      updateCounts();
      $('tableDescription').textContent = `CA ${ca} · Sort ${state.sortKey} ${state.sortDirection}`;
    } catch (error) {
      if (sequence !== state.queryVersion) return;
      state.rows = [];
      state.total = 0;
      drawTable();
      updateCounts();
      notify(error.message, 'error');
      $('tableDescription').textContent = 'Unable to load certificates';
    } finally {
      if (sequence === state.queryVersion) state.busy = false;
    }
  }
  function formatDate(value) {
    if (!value) return '—';
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return String(value);
    return new Intl.DateTimeFormat('fr-FR', { dateStyle: 'short', timeStyle: 'short' }).format(date);
  }
  function cell(row, value, className = '') {
    const td = document.createElement('td');
    td.textContent = value === null || value === undefined || value === '' ? '—' : String(value);
    if (className) td.className = className;
    row.appendChild(td);
    return td;
  }
  function badgeCell(row, label, kind) {
    const td = document.createElement('td');
    const badge = document.createElement('span');
    badge.className = 'badge ' + kind;
    badge.textContent = label;
    td.appendChild(badge);
    row.appendChild(td);
  }
  function drawTable() {
    const tbody = $('certTableBody');
    tbody.replaceChildren();
    if (!state.rows.length) {
      const tr = document.createElement('tr');
      const td = cell(tr, state.ca ? 'No certificates match these filters.' : 'No certificate authority selected.', 'table-empty');
      td.colSpan = 9;
      tbody.appendChild(tr);
    } else {
      const fragment = document.createDocumentFragment();
      for (const record of state.rows) {
        const tr = document.createElement('tr');
        tr.dataset.serial = record.serial;
        tr.tabIndex = 0;
        tr.setAttribute('aria-label', `Certificate ${record.serial} : ${record.subject}`);
        const cbCell = document.createElement('td');
        cbCell.className = 'cell-checkbox';
        const checkbox = document.createElement('input');
        checkbox.type = 'checkbox';
        checkbox.value = record.serial;
        checkbox.checked = state.selected.has(record.serial);
        checkbox.setAttribute('aria-label', `Select ${record.serial}`);
        checkbox.addEventListener('click', (event) => event.stopPropagation());
        checkbox.addEventListener('change', () => { toggleSelected(record.serial, checkbox.checked); });
        cbCell.appendChild(checkbox);
        tr.appendChild(cbCell);
        cell(tr, record.serial, 'serial');
        const subject = cell(tr, record.subject, 'subject-text');
        subject.title = record.subject || '';
        cell(tr, formatDate(record.not_before));
        cell(tr, formatDate(record.not_after));
        const days = cell(tr, record.days_to_expiry);
        if (Number(record.days_to_expiry) <= 30) days.classList.add('days-warning');
        badgeCell(tr, record.revoked ? 'Revoked' : 'Not revoked', record.revoked ? 'red' : 'green');
        badgeCell(tr, record.is_ca ? 'CA' : 'Final', record.is_ca ? 'blue' : 'neutral');
        const filename = cell(tr, record.filename, 'file-text');
        filename.title = record.relative_path || record.filename || '';
        tr.addEventListener('click', () => focusCertificate(record.serial));
        tr.addEventListener('keydown', (event) => keyInTable(event, record.serial));
        fragment.appendChild(tr);
      }
      tbody.appendChild(fragment);
    }
    for (const header of document.querySelectorAll('.sort-header')) {
      const active = header.dataset.sort === state.sortKey;
      header.classList.toggle('active', active);
      header.querySelector('.sort-glyph').textContent = active ? (state.sortDirection === 'ASC' ? '↑' : '↓') : '↕';
    }
    updateSelectionUI();
  }
  function updateCounts() {
    $('statTotal').textContent = state.ca ? fmtNumber(state.total) : '—';
    $('statActive').textContent = state.ca ? fmtNumber(state.rows.filter((row) => !row.revoked).length) : '—';
    $('statRevoked').textContent = state.ca ? fmtNumber(state.rows.filter((row) => row.revoked).length) : '—';
    $('tableCount').textContent = `${fmtNumber(state.rows.length)} of ${fmtNumber(state.total)} certificate(s)`;
    $('tableHint').textContent = state.total > state.rows.length
      ? 'Only visible certificates can be selected. Use Filter action for all matching results.'
      : 'Click: details · checkboxes: multi-select · Shift + arrows: select a range';
    $('filterActionButton').disabled = !state.ca;
    for (const id of ['newCertButton', 'revokeButton', 'unrevokeButton', 'deleteButton', 'resignButton', 'caDetailsButton']) {
      $(id).disabled = !state.ca;
    }
    updateSelectionUI();
  }
  function updateSelectionUI() {
    $('statSelected').textContent = fmtNumber(state.selected.size);
    $('selectionCount').textContent = fmtNumber(state.selected.size);
    $('selectionBar').hidden = !state.selected.size;
    const allVisibleSelected = state.rows.length > 0 && state.rows.every((r) => state.selected.has(r.serial));
    const someVisibleSelected = state.rows.some((r) => state.selected.has(r.serial));
    $('headCheck').checked = allVisibleSelected;
    $('headCheck').indeterminate = someVisibleSelected && !allVisibleSelected;
    $('selectAllButton').textContent = allVisibleSelected ? 'Deselect all' : 'Select all';
    $('selectAllButton').disabled = !state.rows.length;
    $('clearSelectionButton').disabled = !state.selected.size;
    for (const tr of $('certTableBody').querySelectorAll('tr[data-serial]')) {
      const serial = tr.dataset.serial;
      tr.classList.toggle('active', state.focused === serial);
      tr.classList.toggle('selected', state.selected.has(serial));
      const checkbox = tr.querySelector('input[type=checkbox]');
      if (checkbox) checkbox.checked = state.selected.has(serial);
    }
  }
  function toggleSelected(serial, selected) {
    if (selected) state.selected.add(serial);
    else state.selected.delete(serial);
    updateSelectionUI();
  }
  function selectVisible(checked) {
    for (const record of state.rows) {
      if (checked) state.selected.add(record.serial);
      else state.selected.delete(record.serial);
    }
    updateSelectionUI();
  }
  function selectRange(from, to) {
    const indices = state.rows.map((row) => row.serial);
    const first = indices.indexOf(from);
    const last = indices.indexOf(to);
    if (first === -1 || last === -1) return;
    for (let i = Math.min(first, last); i <= Math.max(first, last); i++) state.selected.add(indices[i]);
    updateSelectionUI();
  }
  function keyInTable(event, serial) {
    if (event.key === ' ' || event.key === 'Spacebar') {
      event.preventDefault();
      toggleSelected(serial, !state.selected.has(serial));
    } else if (event.key === 'Enter') {
      event.preventDefault(); focusCertificate(serial);
    } else if (event.key === 'ArrowDown' || event.key === 'ArrowUp' || event.key === 'Home' || event.key === 'End') {
      event.preventDefault();
      const rows = state.rows.map((row) => row.serial);
      const idx = rows.indexOf(serial);
      const to = event.key === 'Home' ? 0 : event.key === 'End' ? rows.length - 1 : Math.max(0, Math.min(rows.length - 1, idx + (event.key === 'ArrowUp' ? -1 : 1)));
      if (event.shiftKey) selectRange(serial, rows[to]);
      const target = [...$('certTableBody').querySelectorAll('tr[data-serial]')][to];
      if (target) target.focus();
      focusCertificate(rows[to]);
    }
  }
  const contentButtons = ['viewPemButton', 'downloadPemButton', 'downloadDerButton', 'downloadChainButton'];
  function toggleCertificateContent(visible) {
    for (const id of contentButtons) $(id).hidden = !visible;
  }
  function resetDetail() {
    toggleCertificateContent(false);
    $('detailSubtitle').textContent = 'Select a certificate row';
    const holder = document.createElement('div');
    holder.className = 'detail-placeholder';
    for (const [tag, label, className] of [
      ['span', '◈', 'detail-illustration'], ['strong', 'No certificate selected', ''],
      ['span', 'Metadata and extensions will appear here.', ''],
    ]) {
      const element = document.createElement(tag);
      element.textContent = label;
      if (className) element.className = className;
      holder.appendChild(element);
    }
    $('detailContent').replaceChildren(holder);
  }
  async function focusCertificate(serial) {
    if (!serial || !state.ca) return;
    state.focused = serial;
    updateSelectionUI();
    const serialVersion = ++state.detailVersion;
    const ca = state.ca;
    toggleCertificateContent(false);
    $('detailSubtitle').textContent = `Certificate ${serial} · loading…`;
    try {
      const detail = await api('GET', pathForCA() + '/certificates/' + encodeURIComponent(serial));
      if (serialVersion !== state.detailVersion || state.ca !== ca) return;
      renderDetail(detail);
      toggleCertificateContent(true);
    } catch (error) {
      if (serialVersion === state.detailVersion) {
        $('detailSubtitle').textContent = 'Failed to load certificate details';
        notify(error.message, 'error');
      }
    }
  }
  function at(obj, ...keys) {
    return keys.reduce((value, key) => (value && typeof value === 'object' ? value[key] : undefined), obj);
  }
  function display(value) {
    if (value === undefined || value === null || value === '') return '—';
    if (typeof value === 'boolean') return value ? 'Oui' : 'Non';
    if (Array.isArray(value)) return value.map((item) => typeof item === 'object' ? (item.display || item.name || JSON.stringify(item)) : String(item)).join(', ') || '—';
    if (typeof value === 'object') return value.display || JSON.stringify(value);
    return String(value);
  }
  async function certificateContent(format) {
    if (!state.ca || !state.focused) throw new Error('Select a certificate.');
    const ca = state.ca;
    const serial = state.focused;
    const path = '/cas/' + encodeURIComponent(ca) + '/certificates/' +
      encodeURIComponent(serial) + '/content?format=' + encodeURIComponent(format);
    const content = await api('GET', path);
    if (ca !== state.ca || serial !== state.focused) return null;
    if (content.format !== format || !['utf-8', 'base64'].includes(content.encoding) ||
        typeof content.content !== 'string' || typeof content.filename !== 'string') {
      throw new Error('Invalid certificate format in the API response.');
    }
    return content;
  }
  async function viewPem() {
    const content = await certificateContent('pem');
    if (content) showReadOnly('Public certificate · PEM', content.content,
      'Public X.509 certificate from CA "' + state.ca + '". No private key.');
  }
  async function downloadCertificate(format) {
    const content = await certificateContent(format);
    if (!content) return;
    let bytes;
    if (content.encoding === 'base64') {
      const binary = atob(content.content);
      bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
    } else {
      bytes = new TextEncoder().encode(content.content);
    }
    const url = URL.createObjectURL(new Blob([bytes], {type: content.mime_type || 'application/octet-stream'}));
    const link = document.createElement('a');
    link.href = url;
    // The filename is set by the API from the verified hexadecimal serial.
    link.download = content.filename;
    link.hidden = true;
    document.body.appendChild(link);
    try { link.click(); } finally { link.remove(); setTimeout(() => URL.revokeObjectURL(url), 2000); }
  }

  function renderDetail(detail) {
    $('detailSubtitle').textContent = `Serial number: ${detail.serial_hex || detail.serial_number || state.focused}`;
    const sections = [
      ['Identity', [
        ['Subject', detail.subject], ['Issuer', detail.issuer], ['Serial number', detail.serial_hex],
        ['Version', detail.version], ['Fichier', detail.file],
      ]],
      ['Validity and status', [
        ['Valid from', detail.not_valid_before], ['Valid until', detail.not_valid_after],
        ['Revoked', detail.revoked], ['CA certificate', at(detail, 'basic_constraints', 'is_ca')],
        ['Path length', at(detail, 'basic_constraints', 'path_length')],
      ]],
      ['Cryptographie', [
        ['Signature', at(detail, 'signature', 'display')], ['Hash', at(detail, 'signature', 'hash')],
        ['Public key', at(detail, 'public_key', 'type')], ['Bits', at(detail, 'public_key', 'bits')],
        ['SHA-256', at(detail, 'fingerprints', 'sha256')],
      ]],
      ['Extensions X.509', [
        ['SAN', detail.san], ['Key Usage', detail.key_usage], ['Extended Key Usage', detail.extended_key_usage],
        ['Policies', detail.certificate_policies], ['CDP', detail.crl_distribution_points],
      ]],
      ['AD CS / Microsoft', [
        ['Template', at(detail, 'microsoft', 'template', 'name')],
        ['Template OID', at(detail, 'microsoft', 'template', 'oid')],
        ['Object SID', at(detail, 'microsoft', 'object_sid')],
        ['Application policies', at(detail, 'microsoft', 'application_policies')],
      ]],
      ['Key identifiers', [
        ['Subject Key ID', detail.subject_key_identifier],
        ['Authority Key ID', detail.authority_key_identifier],
      ]],
    ];
    const grid = document.createElement('div');
    grid.className = 'detail-grid';
    for (const [title, properties] of sections) {
      const group = document.createElement('section');
      group.className = 'detail-group';
      const heading = document.createElement('h3');
      heading.textContent = title;
      const dl = document.createElement('dl');
      dl.className = 'detail-list';
      for (const [key, value] of properties) {
        const dt = document.createElement('dt'); dt.textContent = key;
        const dd = document.createElement('dd'); dd.textContent = display(value); dd.title = display(value);
        dl.append(dt, dd);
      }
      group.append(heading, dl);
      grid.appendChild(group);
    }
    const raw = document.createElement('details'); raw.className = 'detail-json';
    const summary = document.createElement('summary'); summary.textContent = 'Show all metadata (JSON)';
    const pre = document.createElement('pre'); pre.textContent = JSON.stringify(detail, null, 2);
    raw.append(summary, pre);
    $('detailContent').replaceChildren(grid, raw);
  }

  let dialogSubmitHandler = null;
  function openDialog({title, description = '', submitText = 'Valider', destructive = false, showSubmit = true, onSubmit = null}) {
    $('dialogTitle').textContent = title;
    $('dialogDescription').textContent = description;
    $('dialogFields').replaceChildren();
    $('dialogError').hidden = true;
    $('dialogSubmit').hidden = !showSubmit;
    $('dialogSubmit').textContent = submitText;
    $('dialogSubmit').className = 'btn ' + (destructive ? 'btn-danger' : 'btn-primary');
    $('dialogSubmit').disabled = false;
    $('dialogCancel').textContent = showSubmit ? 'Cancel' : 'Close';
    dialogSubmitHandler = onSubmit;
    if (!$('dialog').open) $('dialog').showModal();
    return $('dialogFields');
  }
  function modalError(error) {
    $('dialogError').textContent = typeof error === 'string' ? error : error.message;
    $('dialogError').hidden = false;
  }
  function closeDialog() { if ($('dialog').open) $('dialog').close(); }
  async function submitModal(event) {
    event.preventDefault();
    if (!dialogSubmitHandler) return;
    $('dialogError').hidden = true;
    if (!$('dialogForm').reportValidity()) return;
    const callback = dialogSubmitHandler;
    $('dialogSubmit').disabled = true;
    try { await callback(); }
    catch (error) { modalError(error); }
    finally { $('dialogSubmit').disabled = false; }
  }
  function showReadOnly(title, data, description = '') {
    const fields = openDialog({title, description, showSubmit: false});
    const pre = document.createElement('pre');
    pre.className = 'readonly-preview';
    pre.textContent = typeof data === 'string' ? data : JSON.stringify(data, null, 2);
    fields.appendChild(pre);
  }
  function formFields(definition) {
    const grid = document.createElement('div'); grid.className = 'dialog-form-grid';
    const inputs = new Map();
    for (const field of definition) {
      const wrap = document.createElement('div');
      wrap.className = 'dialog-field' + (field.full ? ' full' : '');
      let input;
      if (field.type === 'checkbox') {
        wrap.classList.add('dialog-check');
        input = document.createElement('input');
        input.type = 'checkbox'; input.checked = Boolean(field.default);
        const label = document.createElement('label'); label.textContent = field.label;
        label.prepend(input); wrap.appendChild(label);
      } else {
        const label = document.createElement('label'); label.textContent = field.label;
        wrap.appendChild(label);
        if (field.type === 'select') {
          input = document.createElement('select');
          (field.options || []).forEach((option) => {
            const [value, text] = Array.isArray(option) ? option : [option, option];
            input.add(new Option(text, value));
          });
          if (field.default !== undefined) input.value = String(field.default);
        } else if (field.type === 'textarea') {
          input = document.createElement('textarea');
          input.rows = 4;
        } else {
          input = document.createElement('input');
          input.type = field.type || 'text';
          if (field.min !== undefined) input.min = String(field.min);
          if (field.max !== undefined) input.max = String(field.max);
          if (field.step !== undefined) input.step = String(field.step);
          if (field.maxLength !== undefined) input.maxLength = field.maxLength;
          if (field.default !== undefined) input.value = String(field.default);
          if (field.type === 'file') input.accept = field.accept || '.csr,.pem,.der';
        }
        input.required = Boolean(field.required);
        input.placeholder = field.placeholder || '';
        input.id = 'form-' + field.name;
        label.htmlFor = input.id;
        wrap.appendChild(input);
      }
      inputs.set(field.name, input);
      grid.appendChild(wrap);
    }
    return {grid, inputs};
  }
  function readForm(definition, inputs) {
    const result = {};
    for (const field of definition) {
      const input = inputs.get(field.name);
      if (field.type === 'checkbox') {
        result[field.name] = input.checked;
      } else if (field.type === 'file') {
        if (input.files.length) result[field.name] = input.files[0];
      } else if (input.value.trim() !== '') {
        result[field.name] = field.type === 'number' ? Number(input.value) : input.value.trim();
      }
    }
    return result;
  }
  async function runForm({title, description, fields, url, afterSubmit, success, transform, destructive = false, submitText = 'Run'}) {
    const form = formFields(fields);
    const container = openDialog({
      title, description, submitText, destructive,
      onSubmit: async () => {
        let payload = readForm(fields, form.inputs);
        if (transform) payload = await transform(payload);
        payload.confirm = true;
        const result = await api('POST', typeof url === 'function' ? url() : url, payload);
        closeDialog();
        notify(success || 'Action completed.', 'success');
        if (afterSubmit) await afterSubmit(result);
        if (result?.errors?.length || result?.status === 'denied') showReadOnly('Action result', result);
      },
    });
    container.appendChild(form.grid);
  }

  function actionName(action) {
    return {revoke: 'Revoke', unrevoke: 'Undo revocation', delete: 'Delete'}[action];
  }
  function getActionSelection(mode, options = {}) {
    if (mode === 'filter') {
      syncFilters();
      if (options.eligible && (state.filters.status !== 'any' || state.filters.revocation !== 'any')) {
        throw new Error('The eligible filter cannot be combined with expiration/revocation filters.');
      }
      if (!options.eligible && state.filters.status === 'any' && state.filters.revocation === 'any' && !state.filters.search) {
        throw new Error('Set a status, revocation filter or search before running a filter action.');
      }
      return {filter: {...state.filters, order_by: orderBy(), limit: 0, eligible: !!options.eligible}};
    }
    const serials = state.selected.size ? [...state.selected] : (state.focused ? [state.focused] : []);
    if (!serials.length) throw new Error('Select a certificate or click a row.');
    return {serials};
  }
  async function actionPrompt(action, mode = 'selection', options = {}) {
    if (!state.ca) return notify('Choisissez une CA.', 'error');
    let target;
    try { target = getActionSelection(mode, options); }
    catch (error) { notify(error.message, 'error'); return; }
    const ca = state.ca;
    const label = actionName(action);
    const isDelete = action === 'delete';
    const description = isDelete
      ? 'Eligible certificates and their keys, when present, will be moved to .trash. The certificate must be expired or revoked.'
      : 'Serial numbers will be handled in one adcs_tool call. The CRL will be updated once per batch if the imported ADCS implementation supports batch revocation.';
    const modal = openDialog({
      title: label + (mode === 'filter' ? ' by filter' : ' certificates'),
      description, destructive: isDelete || action === 'revoke', submitText: 'Confirm ' + label.toLowerCase(),
      onSubmit: async () => {
        const result = await api('POST', '/cas/' + encodeURIComponent(ca) + '/certificates/actions/' + action,
          {...target, dry_run: false, confirm: true});
        closeDialog();
        state.selected.clear();
        notify(`${label} : ${result.successes ?? (result.serial ? 1 : '?')} certificate(s) processed.`, result.failures ? 'error' : 'success');
        await loadCertificates();
        if (state.focused) await focusCertificate(state.focused);
        if (result.failures || result.errors?.length) showReadOnly('Result and errors', result);
      },
    });
    $('dialogSubmit').disabled = true;
    const preview = document.createElement('div');
    preview.className = 'preview-block';
    preview.textContent = 'Preparing preview; no changes have been made…';
    modal.appendChild(preview);
    try {
      const dryRun = await api('POST', '/cas/' + encodeURIComponent(ca) + '/certificates/actions/' + action,
        {...target, dry_run: true});
      if (!$('dialog').open || state.ca !== ca || !preview.isConnected) return;
      preview.replaceChildren();
      const count = dryRun.selected ?? (target.serials?.length || 0);
      const summary = document.createElement('strong');
      summary.textContent = `${fmtNumber(count)} certificate(s) affected`;
      preview.appendChild(summary);
      const meta = document.createElement('div');
      meta.textContent = `${mode === 'filter' ? 'All matching filter results' : 'Explicit selection'} · CA ${ca}`;
      preview.appendChild(meta);
      const candidates = dryRun.candidates || (dryRun.serial ? [{serial: dryRun.serial}] : []);
      if (candidates.length) {
        const list = document.createElement('ol');
        for (const candidate of candidates.slice(0, 10)) {
          const item = document.createElement('li');
          item.textContent = `${candidate.serial} ${candidate.subject ? '— ' + candidate.subject : ''}`;
          list.appendChild(item);
        }
        if (candidates.length > 10) {
          const more = document.createElement('li'); more.textContent = `… and ${candidates.length - 10} more`; list.appendChild(more);
        }
        preview.appendChild(list);
      }
      if (dryRun.errors?.length) {
        const caution = document.createElement('div'); caution.className = 'preview-warning';
        caution.textContent = `${dryRun.errors.length} certificate(s) ineligible. Deletion may be partial.`;
        preview.appendChild(caution);
      }
      $('dialogSubmit').disabled = count === 0;
    } catch (error) {
      modalError(error);
      preview.textContent = 'Preview failed. The action will not run.';
      $('dialogSubmit').disabled = true;
    }
  }
  function filterActionDialog() {
    const fields = [
      {name: 'action', label: 'Action to apply to all matching certificates', type: 'select', full: true,
        options: [['revoke', 'Revoke'], ['unrevoke', 'Undo revocation'], ['delete', 'Delete (if eligible)']]},
      {name: 'eligible', label: 'For deletion: all eligible certificates (expired OR revoked)',
        type: 'checkbox', default: false, full: true},
    ];
    const form = formFields(fields);
    const container = openDialog({
      title: 'Action by filter',
      description: 'This action may affect more certificates than the current row limit. A preview will appear before confirmation.',
      submitText: 'Preview',
      onSubmit: async () => {
        const values = readForm(fields, form.inputs);
        if (values.eligible && values.action !== 'delete') throw new Error('Eligible mode only applies to deletion.');
        closeDialog();
        await actionPrompt(values.action, 'filter', {eligible: values.eligible});
      },
    });
    container.appendChild(form.grid);
  }
  async function resignCRL() {
    if (!state.ca) return;
    await runForm({
      title: 'Re-sign CRL', description: `Generate and sign the revocation list for ${state.ca}.`,
      fields: [
        {name: 'bump_number', label: 'Increment CRL number', type: 'checkbox', default: true, full: true},
        {name: 'next_update_hours', label: 'Next update (hours, optional)', type: 'number', min: 1, max: 8760},
      ],
      url: pathForCA() + '/crl/resign', success: 'CRL re-signed.', afterSubmit: loadCertificates,
    });
  }
  async function newCertificate() {
    if (!state.ca) return;
    await runForm({
      title: 'New certificate', description: `Create a certificate signed by ${state.ca}, as in adcs-gui.`,
      url: pathForCA() + '/certificates', submitText: 'Create certificate',
      success: 'Certificate created.', afterSubmit: (result) => { showReadOnly('Generated certificate', result); return loadCertificates(); },
      fields: [
        {name: 'cn', label: 'Common Name (CN)', type: 'text', required: true, full: true, placeholder: 'srv.example.org'},
        {name: 'sans', label: 'SAN (DNS/IP, comma-separated)', type: 'text', full: true, placeholder: 'srv.example.org, 10.0.0.5'},
        {name: 'rsa_bits', label: 'Taille RSA', type: 'select', options: [['2048', '2048'], ['3072', '3072'], ['4096', '4096']], default: '3072'},
        {name: 'valid_days', label: 'Validity (days)', type: 'number', default: 365, min: 1, max: 365000},
        {name: 'crt_path', label: 'Certificate file path (optional)', type: 'text', full: true, placeholder: '/var/lib/adcs/pki/certs/…'},
        {name: 'key_path', label: 'Key file path (optional)', type: 'text', full: true, placeholder: '/var/lib/adcs/pki/private/…'},
      ],
      transform: (payload) => ({...payload, rsa_bits: Number(payload.rsa_bits || 3072),
        sans: (payload.sans || '').split(/[,;]+/).map((item) => item.trim()).filter(Boolean)}),
    });
  }
  async function viewConfig() {
    const info = await api('GET', '/config');
    showReadOnly('Global configuration (sans secrets)', info,
      'Read-only ADCS configuration. Passwords, PINs, tokens and private keys are masked.');
  }
  async function infoCA() {
    if (!state.ca) return;
    const info = await api('GET', pathForCA());
    showReadOnly('Configuration for ' + state.ca, info, 'Public CA data (no private keys).');
  }
  async function advancedAction() {
    const mode = $('advancedSelect').value;
    if (mode === 'config') { await viewConfig(); return; }
    if (mode === 'callbacks') {
      const data = await api('GET', '/' + mode);
      showReadOnly(mode === 'config' ? 'Global configuration' : 'Callbacks / templates', data,
        'Configuration returned by adcs_tool. Sensitive values are masked by ADCS.');
      return;
    }
    if (mode === 'create-ca') {
      await runForm({
        title: 'Create a certificate authority', description: 'Create a root or intermediate CA via adcs_tool.',
        url: '/cas', success: 'CA created.', afterSubmit: async (result) => { await loadCAs(result.id); showReadOnly('New authority', result); },
        fields: [
          {name: 'cn', label: 'Common Name de la CA', required: true, full: true, placeholder: 'CA-Interne'},
          {name: 'aia_crl_base_url', label: 'URL de base AIA/CRL', required: true, full: true, placeholder: 'http://pki.example.org/'},
          {name: 'signer_ca_id', label: 'CA signataire (vide = racine)', type: 'select', full: true,
            options: [['', 'None (root CA)'], ...state.cas.map((ca) => [ca.id, labelForCA(ca)])]},
          {name: 'key_type', label: 'Key type', type: 'select', options: [['rsa', 'RSA'], ['ec', 'Elliptic curve'], ['mldsa', 'ML-DSA']]},
          {name: 'rsa_bits', label: 'RSA bits (si RSA)', type: 'number', default: 4096, min: 2048, max: 16384},
          {name: 'ec_curve', label: 'Courbe EC', type: 'text', default: 'secp256r1'},
          {name: 'mldsa_variant', label: 'ML-DSA variante', type: 'text', default: 'mldsa65'},
          {name: 'valid_days', label: 'Validity (days)', type: 'number', default: 3650, min: 1, max: 365000},
          {name: 'csr_path', label: 'CSR existante (chemin serveur, optionnel)', full: true},
          {name: 'crt_path', label: 'Certificate path (optional)', full: true},
          {name: 'key_path', label: 'Key path (optional)', full: true},
          {name: 'crl_path', label: 'CRL path (optional)', full: true},
        ],
      });
      return;
    }
    if (!state.ca) throw new Error('Select a CA.');
    if (mode === 'create-ket') {
      await runForm({
        title: 'Create KET / CAExchange certificate', description: `CA ${state.ca} · create and configure the exchange certificate.`,
        url: pathForCA() + '/ket', success: 'KET created.', afterSubmit: (result) => showReadOnly('Certificate KET', result),
        fields: [
          {name: 'cn', label: 'Common Name (optionnel)', full: true},
          {name: 'rsa_bits', label: 'RSA bits', type: 'number', default: 4096, min: 2048, max: 16384},
          {name: 'valid_days', label: 'Validity (days)', type: 'number', default: 3650, min: 1, max: 365000},
          {name: 'crt_path', label: 'Certificate path (optional)', full: true},
          {name: 'key_path', label: 'Key path (optional)', full: true},
        ],
      });
    } else if (mode === 'rotate') {
      await runForm({
        title: 'Rotation / renewal', description: 'Renew a certificate if its expiration falls within the chosen threshold.',
        url: pathForCA() + '/certificates/rotate', success: 'Rotation completed.',
        afterSubmit: async (result) => { await loadCertificates(); showReadOnly('Rotation result', result); },
        fields: [
          {name: 'crt_path', label: 'Certificate path on server', required: true, full: true},
          {name: 'key_path', label: 'Key path on server', required: true, full: true},
          {name: 'threshold_days', label: 'Seuil de rotation (jours)', type: 'number', default: 30, min: 0, max: 365000},
          {name: 'valid_days', label: 'Validity (days)', type: 'number', default: 365, min: 1, max: 365000},
          {name: 'write_fullchain_to_crt', label: 'Write full chain into certificate', type: 'checkbox', default: true, full: true},
        ],
      });
    } else if (mode === 'csr') {
      await runForm({
        title: 'Submit CSR', description: `Choose a PEM or DER file. The API identity "${state.username}" will be used for the request and callbacks.`,
        url: pathForCA() + '/csr', success: 'CSR soumise.',
        afterSubmit: (result) => showReadOnly('CSR result', result),
        fields: [
          {name: 'csr_file', label: 'Fichier CSR local (.csr, .pem, .der)', type: 'file', required: true, full: true},
          {name: 'template_oid', label: 'Template OID (or name below)', full: true},
          {name: 'template_name', label: 'Template name (or OID above)', full: true},
        ],
        transform: async (payload) => {
          if (payload.template_oid && payload.template_name) throw new Error('Choose either a template name or an OID.');
          if (!payload.csr_file || payload.csr_file.size > 1_000_000 || payload.csr_file.size === 0) {
            throw new Error('CSR obligatoire, taille comprise entre 1 octet et 1 Mo.');
          }
          const bytes = new Uint8Array(await payload.csr_file.arrayBuffer());
          let binary = '';
          for (let index = 0; index < bytes.length; index += 8192) {
            binary += String.fromCharCode(...bytes.subarray(index, index + 8192));
          }
          delete payload.csr_file;
          payload.csr_base64 = btoa(binary);
          return payload;
        },
      });
    } else if (mode === 'resign-all') {
      await runForm({
        title: 'Re-sign all CRLs', description: 'This action may change multiple CRLs. Check the certificate authorities before confirming.',
        url: '/crls/resign-all', success: 'All CRLs re-signed.',
        afterSubmit: async (result) => { await loadCertificates(); showReadOnly('CRL report', result); },
        fields: [
          {name: 'bump_number', label: 'Increment CRL numbers', type: 'checkbox', default: true, full: true},
          {name: 'next_update_hours', label: 'Next update (hours, optional)', type: 'number', min: 1, max: 8760},
        ],
      });
    }
  }
  function help() {
    showReadOnly('Keyboard shortcuts', [
      ' /             : focus search',
      ' F5            : refresh',
      ' R / U         : revoke / undo revocation',
      ' Suppr         : delete',
      ' Ctrl + N      : new certificate',
      ' Ctrl + R      : re-sign CRL',
      ' Space         : select row (in table)',
      ' Shift+↑/↓     : select a range (in table)',
      ' Ctrl + A      : select visible rows (outside text inputs)',
      ' Escape        : clear selection / close dialog',
      ' ?             : this help',
      '',
      'Multiple revocations are submitted in one batch',
      'to adcs_tool. Preview does not modify certificates or CRLs.',
    ].join('\n'));
  }
  function openSidebar() { $('sidebar').classList.add('open'); $('mobileScrim').hidden = false; }
  function closeSidebar() { $('sidebar').classList.remove('open'); $('mobileScrim').hidden = true; }
  function textInputFocused() {
    const target = document.activeElement;
    return target && (['INPUT', 'TEXTAREA', 'SELECT'].includes(target.tagName) || target.isContentEditable);
  }
  function keyboard(event) {
    if (!$('appView').hidden && !$('dialog').open) {
      if (event.key === 'F5') { event.preventDefault(); loadCertificates(); return; }
      if (event.key === '/' && !textInputFocused()) { event.preventDefault(); $('searchInput').focus(); return; }
      if (event.key === '?' && !textInputFocused()) { event.preventDefault(); help(); return; }
      if (event.ctrlKey && event.key.toLowerCase() === 'n') { event.preventDefault(); newCertificate(); return; }
      if (event.ctrlKey && event.key.toLowerCase() === 'r') { event.preventDefault(); resignCRL(); return; }
      if (event.ctrlKey && event.key.toLowerCase() === 'a' && !textInputFocused()) { event.preventDefault(); selectVisible(true); return; }
      if (textInputFocused()) return;
      if (event.key === 'r' || event.key === 'R') { event.preventDefault(); actionPrompt('revoke'); }
      else if (event.key === 'u' || event.key === 'U') { event.preventDefault(); actionPrompt('unrevoke'); }
      else if (event.key === 'Delete') { event.preventDefault(); actionPrompt('delete'); }
      else if (event.key === 'Escape') { state.selected.clear(); updateSelectionUI(); closeSidebar(); }
    }
  }
  function safeAsync(callback) {
    return (...args) => Promise.resolve().then(() => callback(...args)).catch((error) => notify(error.message, 'error'));
  }
  function wireUp() {
    $('loginForm').addEventListener('submit', login);
    $('loginServer').addEventListener('change', () => {
      if (!state.token) healthCheck();
    });
    $('logoutButton').addEventListener('click', logout);
    $('caSelect').addEventListener('change', safeAsync(() => selectCA($('caSelect').value)));
    let searchTimer = null;
    const updateSearch = () => {
      clearTimeout(searchTimer);
      searchTimer = setTimeout(() => { state.selected.clear(); loadCertificates(); }, 280);
    };
    $('searchInput').addEventListener('input', updateSearch);
    for (const id of ['statusFilter', 'revocationFilter', 'maxRows']) {
      $(id).addEventListener('change', safeAsync(() => { state.selected.clear(); return loadCertificates(); }));
    }
    $('resetFilters').addEventListener('click', () => {
      $('searchInput').value = ''; $('statusFilter').value = 'any';
      $('revocationFilter').value = 'any'; $('maxRows').value = '1000';
      state.selected.clear(); loadCertificates();
    });
    $('reloadButton').addEventListener('click', safeAsync(loadCertificates));
    $('caDetailsButton').addEventListener('click', safeAsync(infoCA));
    $('configButton').addEventListener('click', safeAsync(viewConfig));
    $('viewPemButton').addEventListener('click', safeAsync(viewPem));
    $('downloadPemButton').addEventListener('click', safeAsync(() => downloadCertificate('pem')));
    $('downloadDerButton').addEventListener('click', safeAsync(() => downloadCertificate('der')));
    $('downloadChainButton').addEventListener('click', safeAsync(() => downloadCertificate('fullchain')));
    $('newCertButton').addEventListener('click', safeAsync(newCertificate));
    $('revokeButton').addEventListener('click', () => actionPrompt('revoke'));
    $('unrevokeButton').addEventListener('click', () => actionPrompt('unrevoke'));
    $('deleteButton').addEventListener('click', () => actionPrompt('delete'));
    $('resignButton').addEventListener('click', safeAsync(resignCRL));
    $('advancedButton').addEventListener('click', safeAsync(advancedAction));
    $('swaggerButton').addEventListener('click', () => {
      // Open the API's own documentation origin, even with a separately hosted site.
      const url = apiBase.replace(/\/api\/v1$/, '/api/docs');
      window.open(url, '_blank', 'noopener,noreferrer');
    });
    $('filterActionButton').addEventListener('click', filterActionDialog);
    $('selectAllButton').addEventListener('click', () => selectVisible(!$('headCheck').checked));
    $('headCheck').addEventListener('change', (event) => selectVisible(event.target.checked));
    $('clearSelectionButton').addEventListener('click', () => { state.selected.clear(); updateSelectionUI(); });
    for (const header of document.querySelectorAll('.sort-header')) {
      header.addEventListener('click', () => {
        if (state.sortKey === header.dataset.sort) state.sortDirection = state.sortDirection === 'ASC' ? 'DESC' : 'ASC';
        else { state.sortKey = header.dataset.sort; state.sortDirection = 'ASC'; }
        loadCertificates();
      });
    }
    $('dialogClose').addEventListener('click', closeDialog);
    $('dialogCancel').addEventListener('click', closeDialog);
    $('dialogForm').addEventListener('submit', submitModal);
    $('helpButton').addEventListener('click', help);
    $('themeButton').addEventListener('click', () => {
      const value = document.body.dataset.theme === 'light' ? 'dark' : 'light';
      document.body.dataset.theme = value;
      try { localStorage.setItem('adcs_theme', value); } catch (_error) { /* optional */ }
    });
    $('openSidebar').addEventListener('click', openSidebar);
    $('closeSidebar').addEventListener('click', closeSidebar);
    $('mobileScrim').addEventListener('click', closeSidebar);
    document.addEventListener('keydown', keyboard);
  }
  function initSplitter() {
    const splitter = $('detailSplitter');
    const parent = $('splitArea');
    let fraction = 0.34;
    try {
      const saved = parseFloat(localStorage.getItem('adcs_detail_fraction'));
      if (Number.isFinite(saved) && saved >= .18 && saved <= .75) fraction = saved;
    } catch (_error) { /* stockage optionnel */ }
    const setFraction = (value) => {
      fraction = Math.min(.75, Math.max(.18, value));
      parent.style.setProperty('--details-fr', String(fraction));
    };
    setFraction(fraction);
    let dragging = false;
    splitter.addEventListener('pointerdown', (event) => {
      if (event.button !== 0) return;
      dragging = true;
      splitter.setPointerCapture(event.pointerId);
      event.preventDefault();
    });
    splitter.addEventListener('pointermove', (event) => {
      if (!dragging) return;
      const rect = parent.getBoundingClientRect();
      setFraction((rect.bottom - event.clientY) / rect.height);
    });
    const stop = () => {
      if (!dragging) return;
      dragging = false;
      try { localStorage.setItem('adcs_detail_fraction', String(fraction)); } catch (_error) {}
    };
    splitter.addEventListener('pointerup', stop);
    splitter.addEventListener('pointercancel', stop);
    splitter.addEventListener('keydown', (event) => {
      if (event.key !== 'ArrowUp' && event.key !== 'ArrowDown') return;
      event.preventDefault();
      setFraction(fraction + (event.key === 'ArrowUp' ? .04 : -.04));
      try { localStorage.setItem('adcs_detail_fraction', String(fraction)); } catch (_error) {}
    });
  }
  function init() {
    try {
      const theme = localStorage.getItem('adcs_theme');
      if (theme === 'light' || theme === 'dark') document.body.dataset.theme = theme;
    } catch (_error) { /* optional */ }
    let saved = '';
    try { saved = localStorage.getItem(STORAGE_SERVER_KEY) || ''; } catch (_error) { /* optional */ }
    $('loginServer').value = saved || DEFAULT_API_BASE;
    wireUp();
    initSplitter();
    healthCheck();
  }
  init();
})();
