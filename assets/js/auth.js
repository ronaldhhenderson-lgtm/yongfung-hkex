/* ===================================================================
 * YongFung HKEX Site — Client-side access gate
 * -------------------------------------------------------------------
 * Two-tier auth. Passwords are stored as SHA-256 hashes only.
 * Sessions persist via sessionStorage (cleared when browser closes).
 * General tier has a hard expiry set at build time.
 *
 * NOTE: Client-side gating is obfuscation, not real security.
 *       For production, route through a server/edge Basic-Auth layer.
 * =================================================================== */

(function () {
  'use strict';

  // SHA-256 hashes of the configured passwords — plaintext never appears here.
  var HASH_MASTER  = 'a2e7fc3df012bc227ff036774ed2d0e8aba1fe333629c632b777c831eeb7a43e';
  var HASH_GENERAL = 'bd611a82822ae65bdf2395bb0f2028599baf5380a6300fdd45ca13585a1701d8';

  // General password expires 2026-05-24 (30 days from 2026-04-24 build date).
  var GENERAL_EXPIRES_MS = Date.UTC(2026, 4, 24, 23, 59, 59); // month is 0-indexed → 4 = May

  var STORAGE_KEY = 'yf_auth_session_v1';

  async function sha256Hex(text) {
    var enc = new TextEncoder().encode(text);
    var buf = await crypto.subtle.digest('SHA-256', enc);
    return Array.from(new Uint8Array(buf))
      .map(function (b) { return b.toString(16).padStart(2, '0'); })
      .join('');
  }

  function currentSession() {
    try {
      var raw = sessionStorage.getItem(STORAGE_KEY);
      if (!raw) return null;
      var obj = JSON.parse(raw);
      if (!obj || !obj.tier || !obj.exp) return null;
      if (Date.now() > obj.exp) {
        sessionStorage.removeItem(STORAGE_KEY);
        return null;
      }
      return obj;
    } catch (e) { return null; }
  }

  function saveSession(tier, expMs) {
    try {
      sessionStorage.setItem(STORAGE_KEY, JSON.stringify({ tier: tier, exp: expMs }));
    } catch (e) {}
  }

  function clearSession() {
    try { sessionStorage.removeItem(STORAGE_KEY); } catch (e) {}
  }

  function isLoginPage() {
    var p = window.location.pathname.split('/').pop() || 'index.html';
    return p === 'login.html';
  }

  function redirectToLogin() {
    var target = encodeURIComponent(window.location.pathname.split('/').pop() + window.location.search + window.location.hash);
    var prefix = window.location.pathname.replace(/[^\/]+$/, '');
    window.location.replace(prefix + 'login.html?next=' + target);
  }

  // -------- Guard pages (everything except login.html) --------
  if (!isLoginPage()) {
    if (!currentSession()) {
      document.documentElement.style.visibility = 'hidden';
      redirectToLogin();
      return;
    }
  }

  // -------- Login-page behaviour --------
  function initLoginPage() {
    var form = document.getElementById('login-form');
    if (!form) return;
    var pwInput = document.getElementById('login-pw');
    var errEl   = document.getElementById('login-err');
    var expEl   = document.getElementById('login-exp');

    if (expEl) {
      var d = new Date(GENERAL_EXPIRES_MS);
      expEl.textContent = d.toISOString().slice(0, 10);
    }

    form.addEventListener('submit', async function (ev) {
      ev.preventDefault();
      errEl.textContent = '';
      var pw = pwInput.value || '';
      var h = await sha256Hex(pw);

      if (h === HASH_MASTER) {
        // Master tier — no expiry (tied to sessionStorage lifetime).
        var masterExp = Date.now() + 8 * 60 * 60 * 1000; // 8h session
        saveSession('master', masterExp);
      } else if (h === HASH_GENERAL) {
        if (Date.now() > GENERAL_EXPIRES_MS) {
          errEl.textContent = 'General access password has expired. Please request a renewed password.';
          return;
        }
        var genExp = Math.min(Date.now() + 8 * 60 * 60 * 1000, GENERAL_EXPIRES_MS);
        saveSession('general', genExp);
      } else {
        errEl.textContent = 'Incorrect password.';
        pwInput.value = '';
        pwInput.focus();
        return;
      }

      // Redirect to original target or home
      var params = new URLSearchParams(window.location.search);
      var next = params.get('next') || 'index.html';
      // Strict sanitisation — only allow known site pages
      var allowed = ['index.html','about.html','products.html','solutions.html','technology.html','investors.html'];
      var nextDecoded = decodeURIComponent(next).split('?')[0].split('#')[0];
      if (allowed.indexOf(nextDecoded) === -1) next = 'index.html';
      window.location.replace(next);
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initLoginPage);
  } else {
    initLoginPage();
  }

  // Expose a simple logout hook
  window.yfLogout = function () {
    clearSession();
    var prefix = window.location.pathname.replace(/[^\/]+$/, '');
    window.location.replace(prefix + 'login.html');
  };
})();
