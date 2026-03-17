(function () {
  var storageKey = 'gpa-models-authenticated';
  var ticketParam = 'gpaAuth';
  var returnParam = 'returnTo';
  var ticketLifetimeMs = 12 * 60 * 60 * 1000;
  var secretBytes = new Uint8Array([
    162, 49, 206, 62, 158, 206, 138, 169,
    37, 230, 67, 205, 19, 61, 154, 236,
    148, 137, 172, 179, 188, 246, 219, 77,
    136, 198, 91, 215, 109, 163, 142, 110
  ]);
  var config = window.GpaModelsAuthConfig || {};
  var textEncoder = new TextEncoder();

  function getStorage(kind) {
    try {
      return window[kind];
    } catch (error) {
      return null;
    }
  }

  function readStoredAuth() {
    var sessionStore = getStorage('sessionStorage');

    if (sessionStore && sessionStore.getItem(storageKey) === '1') {
      return true;
    }

    return false;
  }

  function storeAuth() {
    var sessionStore = getStorage('sessionStorage');

    if (sessionStore) {
      sessionStore.setItem(storageKey, '1');
    }
  }

  function getHubPath() {
    return config.hubPath || './';
  }

  function getScriptBaseUrl() {
    var currentScript = document.currentScript;

    if (currentScript && currentScript.src) {
      return new URL('./', currentScript.src);
    }

    var scriptNode = document.querySelector('script[src$="/auth-gate.js"], script[src="./auth-gate.js"], script[src="auth-gate.js"]');

    if (scriptNode && scriptNode.src) {
      return new URL('./', scriptNode.src);
    }

    return new URL('./', window.location.href);
  }

  function getHubUrl() {
    return new URL(getHubPath(), getScriptBaseUrl());
  }

  function normalizePathname(pathname) {
    var normalized = pathname || '/';

    if (normalized.endsWith('/index.html')) {
      normalized = normalized.slice(0, -'index.html'.length);
    }

    if (!normalized.endsWith('/')) {
      var lastSlashIndex = normalized.lastIndexOf('/');
      var lastSegment = normalized.slice(lastSlashIndex + 1);

      if (!lastSegment.includes('.')) {
        normalized += '/';
      }
    }

    return normalized || '/';
  }

  function isHubPage() {
    return normalizePathname(window.location.pathname) === normalizePathname(getHubUrl().pathname);
  }

  function getCurrentReturnTarget() {
    var currentUrl = new URL(window.location.href);
    currentUrl.searchParams.delete(ticketParam);
    currentUrl.searchParams.delete(returnParam);
    return currentUrl.pathname + currentUrl.search + currentUrl.hash;
  }

  function getSafeReturnTarget() {
    var currentUrl = new URL(window.location.href);
    var returnTarget = currentUrl.searchParams.get(returnParam);

    if (!returnTarget) {
      return null;
    }

    try {
      var resolvedUrl = new URL(returnTarget, window.location.href);

      if (resolvedUrl.origin !== currentUrl.origin) {
        return null;
      }

      if (normalizePathname(resolvedUrl.pathname) === normalizePathname(currentUrl.pathname)) {
        return null;
      }

      return resolvedUrl;
    } catch (error) {
      return null;
    }
  }

  function clearPendingState() {
    delete document.documentElement.dataset.authPending;
  }

  function revealProtectedContent() {
    if (config.protectedSelector) {
      var protectedNode = document.querySelector(config.protectedSelector);
      if (protectedNode) {
        protectedNode.classList.remove('hidden');
      }
    }

    clearPendingState();
  }

  function equalBytes(left, right) {
    if (left.length !== right.length) {
      return false;
    }

    var mismatch = 0;
    for (var index = 0; index < left.length; index += 1) {
      mismatch |= left[index] ^ right[index];
    }

    return mismatch === 0;
  }

  function bytesToBase64Url(bytes) {
    var text = '';
    for (var index = 0; index < bytes.length; index += 1) {
      text += String.fromCharCode(bytes[index]);
    }

    return btoa(text).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
  }

  function mergeBytes(left, right) {
    var merged = new Uint8Array(left.length + right.length);
    merged.set(left, 0);
    merged.set(right, left.length);
    return merged;
  }

  async function digestBytes(bytes) {
    var digest = await window.crypto.subtle.digest('SHA-256', bytes);
    return new Uint8Array(digest);
  }

  async function createTicket() {
    var expiresAt = Date.now() + ticketLifetimeMs;
    var expiryBytes = textEncoder.encode(String(expiresAt));
    var signatureSource = mergeBytes(secretBytes, expiryBytes);
    var digest = await digestBytes(signatureSource);
    var signature = bytesToBase64Url(digest.slice(0, 16));
    return String(expiresAt) + '.' + signature;
  }

  async function verifyTicket(ticket) {
    if (!ticket) {
      return false;
    }

    var separatorIndex = ticket.indexOf('.');
    if (separatorIndex <= 0) {
      return false;
    }

    var expiryText = ticket.slice(0, separatorIndex);
    var signatureText = ticket.slice(separatorIndex + 1);
    var expiresAt = Number(expiryText);

    if (!Number.isFinite(expiresAt) || expiresAt < Date.now()) {
      return false;
    }

    var expectedTicket = await createTicketFromExpiry(expiryText);
    return expectedTicket === ticket && signatureText.length > 0;
  }

  async function createTicketFromExpiry(expiryText) {
    var expiryBytes = textEncoder.encode(expiryText);
    var signatureSource = mergeBytes(secretBytes, expiryBytes);
    var digest = await digestBytes(signatureSource);
    var signature = bytesToBase64Url(digest.slice(0, 16));
    return expiryText + '.' + signature;
  }

  function removeTicketFromUrl() {
    var currentUrl = new URL(window.location.href);
    if (!currentUrl.searchParams.has(ticketParam)) {
      return;
    }

    currentUrl.searchParams.delete(ticketParam);
    window.history.replaceState({}, document.title, currentUrl.toString());
  }

  function redirectToHub() {
    var currentUrl = new URL(window.location.href);
    var hubUrl = getHubUrl();
    hubUrl.searchParams.set(returnParam, getCurrentReturnTarget());

    if (currentUrl.searchParams.has(ticketParam)) {
      hubUrl.searchParams.set(ticketParam, currentUrl.searchParams.get(ticketParam));
    }

    window.location.replace(hubUrl.toString());
  }

  async function redirectToReturnTarget() {
    var returnUrl = getSafeReturnTarget();

    if (!returnUrl) {
      return false;
    }

    var ticket = await createTicket();
    returnUrl.searchParams.set(ticketParam, ticket);
    window.location.replace(returnUrl.toString());
    return true;
  }

  async function decorateLinks() {
    if (!config.linkSelector) {
      return;
    }

    var ticket = await createTicket();
    var links = document.querySelectorAll(config.linkSelector);

    links.forEach(function (link) {
      var href = link.getAttribute('href');
      if (!href || href.startsWith('#')) {
        return;
      }

      var targetUrl = new URL(href, window.location.href);
      targetUrl.searchParams.set(ticketParam, ticket);
      link.setAttribute('href', targetUrl.toString());
    });
  }

  function injectStyles() {
    if (document.getElementById('gpa-models-auth-style')) {
      return;
    }

    var style = document.createElement('style');
    style.id = 'gpa-models-auth-style';
    style.textContent = [
      '.gpa-auth-overlay{position:fixed;inset:0;z-index:2147483647;display:flex;align-items:center;justify-content:center;padding:24px;background:rgba(2,6,23,0.95);backdrop-filter:blur(10px);}',
      '.gpa-auth-card{width:min(100%,28rem);border:1px solid rgba(255,255,255,0.12);border-radius:24px;background:rgba(255,255,255,0.06);padding:32px;box-shadow:0 24px 80px rgba(2,6,23,0.45);color:#f8fafc;font-family:-apple-system,BlinkMacSystemFont,\'Segoe UI\',sans-serif;}',
      '.gpa-auth-row{display:flex;align-items:center;gap:16px;}',
      '.gpa-auth-logo{display:flex;height:48px;width:48px;align-items:center;justify-content:center;overflow:hidden;border-radius:14px;background:#0f172a;border:1px solid rgba(255,255,255,0.08);font-size:12px;color:#cbd5e1;}',
      '.gpa-auth-logo img{height:100%;width:100%;object-fit:contain;}',
      '.gpa-auth-kicker{margin:0 0 4px;font-size:11px;font-weight:600;letter-spacing:0.3em;text-transform:uppercase;color:#94a3b8;}',
      '.gpa-auth-title{margin:0;font-size:20px;font-weight:600;line-height:1.2;color:#fff;}',
      '.gpa-auth-copy{margin:24px 0 0;font-size:14px;line-height:1.6;color:#cbd5e1;}',
      '.gpa-auth-form{margin-top:24px;display:grid;gap:16px;}',
      '.gpa-auth-label{display:block;margin-bottom:8px;font-size:14px;font-weight:500;color:#e2e8f0;}',
      '.gpa-auth-input{width:100%;box-sizing:border-box;border:1px solid rgba(255,255,255,0.12);border-radius:18px;background:rgba(2,6,23,0.75);padding:14px 16px;font-size:16px;color:#fff;outline:none;}',
      '.gpa-auth-input::placeholder{color:#64748b;}',
      '.gpa-auth-input:focus{border-color:rgba(103,232,249,0.6);box-shadow:0 0 0 4px rgba(103,232,249,0.18);}',
      '.gpa-auth-error{display:none;margin:0;font-size:14px;color:#fda4af;}',
      '.gpa-auth-error.is-visible{display:block;}',
      '.gpa-auth-button{width:100%;border:0;border-radius:18px;background:#67e8f9;padding:14px 16px;font-size:14px;font-weight:600;color:#082f49;cursor:pointer;transition:background-color 0.15s ease;}',
      '.gpa-auth-button:hover{background:#a5f3fc;}',
      '.gpa-auth-button:focus{outline:none;box-shadow:0 0 0 4px rgba(103,232,249,0.18);}',
      '@media (max-width:640px){.gpa-auth-card{padding:24px;border-radius:20px;}}'
    ].join('');
    document.head.appendChild(style);
  }

  function createOverlay() {
    injectStyles();

    var overlay = document.createElement('div');
    overlay.className = 'gpa-auth-overlay';
    overlay.innerHTML = [
      '<div class="gpa-auth-card">',
      '  <div class="gpa-auth-row">',
      '    <div class="gpa-auth-logo" aria-hidden="true">',
      '      <img src="../gpa-flow-builder/src/assets/automate-logo-white.png" alt="" onerror="this.remove(); this.parentElement.textContent=\'GP\';" />',
      '    </div>',
      '    <div>',
      '      <p class="gpa-auth-kicker">Restricted Access</p>',
      '      <h1 class="gpa-auth-title">Enter password to continue</h1>',
      '    </div>',
      '  </div>',
      '  <p class="gpa-auth-copy">This page is restricted to internal users. Enter the access password to continue.</p>',
      '  <form class="gpa-auth-form">',
      '    <div>',
      '      <label class="gpa-auth-label" for="gpa-auth-input">Password</label>',
      '      <input id="gpa-auth-input" class="gpa-auth-input" name="password" type="password" autocomplete="current-password" placeholder="Enter access password" required />',
      '    </div>',
      '    <p class="gpa-auth-error" id="gpa-auth-error">Incorrect password. Try again.</p>',
      '    <button class="gpa-auth-button" type="submit">Unlock</button>',
      '  </form>',
      '</div>'
    ].join('');

    return overlay;
  }

  async function validatePassword(value) {
    var passwordBytes = textEncoder.encode(value);
    var digest = await digestBytes(passwordBytes);
    return equalBytes(digest, secretBytes);
  }

  async function showGate() {
    if (!window.crypto || !window.crypto.subtle) {
      clearPendingState();
      window.alert('This browser cannot validate the password for this page.');
      return;
    }

    var overlay = createOverlay();
    var form = overlay.querySelector('form');
    var input = overlay.querySelector('#gpa-auth-input');
    var error = overlay.querySelector('#gpa-auth-error');

    form.addEventListener('submit', async function (event) {
      event.preventDefault();
      error.classList.remove('is-visible');

      if (await validatePassword(input.value)) {
        storeAuth();
        overlay.remove();
        input.value = '';

        if (await redirectToReturnTarget()) {
          return;
        }

        await decorateLinks();
        revealProtectedContent();
        return;
      }

      error.classList.add('is-visible');
      input.select();
    });

    document.body.appendChild(overlay);
    clearPendingState();
    input.focus();
  }

  async function init() {
    var currentUrl = new URL(window.location.href);
    var providedTicket = currentUrl.searchParams.get(ticketParam);
    var hasTicket = await verifyTicket(providedTicket);
    var isAuthenticated = readStoredAuth() || hasTicket;

    if (hasTicket) {
      storeAuth();
      removeTicketFromUrl();
    }

    if (!isAuthenticated && !isHubPage()) {
      redirectToHub();
      return;
    }

    if (isAuthenticated) {
      if (isHubPage() && await redirectToReturnTarget()) {
        return;
      }

      await decorateLinks();
      revealProtectedContent();
      return;
    }

    await showGate();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function () {
      init();
    });
    return;
  }

  init();
})();