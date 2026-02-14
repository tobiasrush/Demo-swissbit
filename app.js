/**
 * Demo-swissbit — Progressive device trust + passwordless login:
 *
 *  1. Trust Device  (first visit)
 *     - Enrolls iShield USB key via raw WebAuthn (navigator.credentials.create)
 *     - Immediately enrolls ZSM + Passkeys+ via Ideem SDK
 *     - Credential ID stored in localStorage, ZSM state in IndexedDB
 *
 *  2. Login  (returning user)
 *     - Authenticates with Passkeys+ only — no USB key touch needed
 *     - Token validated server-side via zsm_app_config.json credentials
 *
 *  3. Protected Actions  (step-up auth)
 *     - Each action re-authenticates via Passkeys+ for authorization
 *
 *  State managed by reactive State class (state.js)
 */

import { UMFAClient } from '@ideem/zsm-client-sdk';
import PasskeysPlus from '@ideem/plugins.passkeys-plus'; // Side-effect import: registers Passkeys+ plugin with the SDK

// ---------------------------------------------------------------------------
// Shared UI helper
// ---------------------------------------------------------------------------
function showFlash(elementId, message, state, duration = 3000) {
  const el = document.getElementById(elementId);
  if (!el) return;
  el.textContent = message;
  el.className = 'flash ' + state;
  setTimeout(() => { el.textContent = ''; el.className = 'flash'; }, duration);
}

function getUsername() {
  return document.getElementById('username')?.value?.trim().toLowerCase() || '';
}

// ---------------------------------------------------------------------------
// Confirmation Popup helpers
// ---------------------------------------------------------------------------
let popupResolve = null;

let popupPreviousFocus = null;

function showPopup(message) {
  return new Promise((resolve) => {
    popupPreviousFocus = document.activeElement;
    document.getElementById('popup-message').textContent = message;
    const popup = document.getElementById('confirm-popup');
    popup.style.display = 'flex';
    popupResolve = resolve;
    document.getElementById('popup-continue').focus();
    document.addEventListener('keydown', popupKeyHandler);
  });
}

function popupKeyHandler(e) {
  if (e.key === 'Escape') {
    hidePopup('cancel');
    return;
  }
  if (e.key === 'Tab') {
    const cancelBtn = document.getElementById('popup-cancel');
    const continueBtn = document.getElementById('popup-continue');
    if (e.shiftKey && document.activeElement === cancelBtn) {
      e.preventDefault();
      continueBtn.focus();
    } else if (!e.shiftKey && document.activeElement === continueBtn) {
      e.preventDefault();
      cancelBtn.focus();
    }
  }
}

function hidePopup(action) {
  document.removeEventListener('keydown', popupKeyHandler);
  document.getElementById('confirm-popup').style.display = 'none';
  if (popupPreviousFocus) {
    popupPreviousFocus.focus();
    popupPreviousFocus = null;
  }
  if (popupResolve) {
    popupResolve(action);
    popupResolve = null;
  }
}

// ---------------------------------------------------------------------------
// FIDO2 USB Key — Raw WebAuthn helpers
// ---------------------------------------------------------------------------
const FIDO2_STORAGE_PREFIX = 'fido2_credential:';

function fido2StorageKey() {
  const user = getUsername();
  return user ? FIDO2_STORAGE_PREFIX + user : null;
}

const SUSPENDED_STORAGE_PREFIX = 'passkeys_suspended:';
const PASSKEYS_TOGGLE_PREFIX = 'actions_passkeys_toggle:';

function isSuspended() {
  const user = getUsername();
  const key = user ? SUSPENDED_STORAGE_PREFIX + user : null;
  return key ? localStorage.getItem(key) === 'true' : false;
}

function setSuspended(value) {
  const user = getUsername();
  const key = user ? SUSPENDED_STORAGE_PREFIX + user : null;
  if (!key) return;
  value ? localStorage.setItem(key, 'true') : localStorage.removeItem(key);
}

function getPasskeysToggle() {
  const user = getUsername();
  const key = user ? PASSKEYS_TOGGLE_PREFIX + user : null;
  if (!key) return true;
  const val = localStorage.getItem(key);
  return val === null ? true : val === 'true';
}

function setPasskeysToggle(value) {
  const user = getUsername();
  const key = user ? PASSKEYS_TOGGLE_PREFIX + user : null;
  if (!key) return;
  localStorage.setItem(key, String(value));
}

function bufferToBase64url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function hashSHA256(input, format = 'hex') {
  if (typeof input !== 'string') throw new TypeError('hashSHA256 expects a string input.');
  const data = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest('SHA-256', data);
  const bytes = new Uint8Array(digest);
  if (format === 'base64') {
    let binary = '';
    bytes.forEach(byte => binary += String.fromCharCode(byte));
    return btoa(binary);
  }
  return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
}

function updateChallengeDisplay(challenge, signedChallenge) {
  const PREVIEW_LEN = 15;
  const isReset = challenge === '--';
  const container = document.getElementById('passkeys-challenge-display');
  const prev = document.getElementById('challenge-preview');
  const full = document.getElementById('challenge-full');
  const sPrev = document.getElementById('signed-challenge-preview');
  const sFull = document.getElementById('signed-challenge-full');
  if (prev && full) {
    prev.textContent = challenge.substring(0, PREVIEW_LEN) + (challenge.length > PREVIEW_LEN ? '...' : '');
    full.textContent = challenge;
  }
  if (sPrev && sFull) {
    sPrev.textContent = signedChallenge.substring(0, PREVIEW_LEN) + (signedChallenge.length > PREVIEW_LEN ? '...' : '');
    sFull.textContent = signedChallenge;
  }
  if (container) container.hidden = isReset;
  document.getElementById('challenge-details')?.removeAttribute('open');
  document.getElementById('signed-challenge-details')?.removeAttribute('open');
}

function updateIShieldChallengeDisplay(challenge, signedChallenge) {
  const PREVIEW_LEN = 15;
  const container = document.getElementById('ishield-challenge-display');
  const prev = document.getElementById('ishield-challenge-preview');
  const full = document.getElementById('ishield-challenge-full');
  const sPrev = document.getElementById('ishield-signed-challenge-preview');
  const sFull = document.getElementById('ishield-signed-challenge-full');
  if (prev && full) {
    prev.textContent = challenge.substring(0, PREVIEW_LEN) + (challenge.length > PREVIEW_LEN ? '...' : '');
    full.textContent = challenge;
  }
  if (sPrev && sFull) {
    sPrev.textContent = signedChallenge.substring(0, PREVIEW_LEN) + (signedChallenge.length > PREVIEW_LEN ? '...' : '');
    sFull.textContent = signedChallenge;
  }
  if (container) container.hidden = false;
  document.getElementById('ishield-challenge-details')?.removeAttribute('open');
  document.getElementById('ishield-signed-challenge-details')?.removeAttribute('open');
}

function updateAuthIcons({ ishield = false, zsm = false, passkeys = false } = {}) {
  document.getElementById('icon-ishield').hidden = !ishield;
  document.getElementById('icon-zsm').hidden = !zsm;
  document.getElementById('icon-passkeys').hidden = !passkeys;
  const ishieldDisplay = document.getElementById('ishield-challenge-display');
  if (ishieldDisplay) ishieldDisplay.hidden = !ishield;
}

function base64urlToBuffer(base64url) {
  const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64 + '='.repeat((4 - base64.length % 4) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

/**
 * Enroll an iShield USB key via raw WebAuthn.
 * @param {boolean} silent — if true, suppress flash messages (caller handles UI)
 */
async function webauthnEnroll(silent = false) {
  const user = getUsername() || 'demo-user';
  const userId = new TextEncoder().encode(user);
  const challenge = crypto.getRandomValues(new Uint8Array(32));

  console.log('[FIDO2 Enroll] Starting enrollment for user:', user);

  try {
    const options = {
      publicKey: {
        rp: { name: 'Demo Swissbit', id: location.hostname },
        user: { id: userId, name: user, displayName: user },
        challenge,
        pubKeyCredParams: [
          { alg: -7, type: 'public-key' },   // ES256
          { alg: -257, type: 'public-key' }   // RS256
        ],
        authenticatorSelection: {
          authenticatorAttachment: 'cross-platform',
          userVerification: 'discouraged',
          residentKey: 'discouraged'
        },
        attestation: 'none',
        timeout: 60000
      }
    };
    console.log('[FIDO2 Enroll] Options:', JSON.stringify({
      rp: options.publicKey.rp,
      user: { name: user, displayName: user },
      authenticatorSelection: options.publicKey.authenticatorSelection,
      attestation: options.publicKey.attestation,
      timeout: options.publicKey.timeout
    }, null, 2));

    const credential = await navigator.credentials.create(options);

    const stored = {
      id: bufferToBase64url(credential.rawId),
      createdAt: new Date().toISOString()
    };
    localStorage.setItem(FIDO2_STORAGE_PREFIX + user, JSON.stringify(stored));

    console.log('[FIDO2 Enroll] Success:', {
      credentialId: stored.id,
      type: credential.type,
      authenticatorAttachment: credential.authenticatorAttachment,
      createdAt: stored.createdAt
    });

    if (!silent) showFlash('flash-status', 'Key enrolled successfully', 'success');
  } catch (err) {
    console.error('[FIDO2 Enroll] Error:', { name: err.name, message: err.message });
    if (!silent) {
      if (err.name === 'NotAllowedError') {
        showFlash('flash-status', 'Cancelled or timed out', 'failure');
      } else if (err.name === 'SecurityError') {
        showFlash('flash-status', 'Security error — try HTTPS or localhost', 'failure');
      } else if (err.name === 'InvalidStateError') {
        showFlash('flash-status', 'Key already registered for this user', 'failure');
      } else {
        showFlash('flash-status', err.message || 'Enrollment failed', 'failure');
      }
    }
    throw err; // Re-throw so callers can handle
  }
}

/**
 * Authenticate with an iShield USB key via raw WebAuthn.
 * Uses the stored credential ID to restrict to the enrolled key.
 */
async function webauthnAuthenticate() {
  const user = getUsername();
  if (!user) return false;

  const key = FIDO2_STORAGE_PREFIX + user;
  const stored = localStorage.getItem(key);
  if (!stored) {
    showFlash('flash-status', 'No iShield key enrolled for this user', 'failure');
    return false;
  }

  const { id: credId } = JSON.parse(stored);
  const credentialId = base64urlToBuffer(credId);
  const challenge = crypto.getRandomValues(new Uint8Array(32));

  console.log('[FIDO2 Auth] Starting authentication for user:', user);

  try {
    const assertion = await navigator.credentials.get({
      publicKey: {
        challenge,
        rpId: location.hostname,
        allowCredentials: [{ id: credentialId, type: 'public-key', transports: ['usb'] }],
        userVerification: 'discouraged',
        timeout: 60000
      }
    });
    console.log('[FIDO2 Auth] Success');

    // Extract challenge and signature from the assertion
    try {
      const clientDataHash = await hashSHA256(
        new TextDecoder().decode(assertion.response.clientDataJSON)
      );
      const signatureHex = Array.from(
        new Uint8Array(assertion.response.signature),
        byte => byte.toString(16).padStart(2, '0')
      ).join('');
      updateIShieldChallengeDisplay(clientDataHash, signatureHex);
    } catch (err) {
      console.warn('[FIDO2 Auth] Could not extract challenge data:', err.message);
    }

    return true;
  } catch (err) {
    console.error('[FIDO2 Auth] Error:', { name: err.name, message: err.message });
    if (err.name === 'NotAllowedError') {
      showFlash('flash-status', 'Cancelled or timed out', 'failure');
    } else {
      showFlash('flash-status', err.message || 'Authentication failed', 'failure');
    }
    return false;
  }
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------
const STATE = new State({
  loginID: null,
  credentialsValid: false,
  token: null
});

// ---------------------------------------------------------------------------
// Config & client
// ---------------------------------------------------------------------------
let zsmAppConfig = null;
let umfaClient = null;

const configLoaded = fetch('./zsm_app_config.json')
  .then(res => res.json())
  .then(config => {
    // Localhost override: zero out hex credential segments so the app
    // initializes without real Ideem server credentials.
    // On Vercel, real credentials from zsm_app_config.json are used as-is.
    if (/localhost:\d+/.test(window.location.host)) {
      for (const key in config) {
        if (typeof config[key] === 'string') {
          config[key] = config[key].replace(/[a-f0-9]{4}/g, '0000');
        }
      }
      config.application_environment = 'test';
      console.log('[CONFIG] Using localhost test credentials');
    }
    console.log('[CONFIG] Loaded:', JSON.stringify(config, null, 2));
    zsmAppConfig = config;
  });

// ---------------------------------------------------------------------------
// Action labels for protected actions
// ---------------------------------------------------------------------------
const PROTECTED_ACTION_LABELS = {
  'make-payment': 'Make Payment',
  'transfer-money': 'Transfer Money',
  'change-setting': 'Change Setting',
  'add-beneficiary': 'Add Beneficiary'
};

// ---------------------------------------------------------------------------
// initializeZSMClient
// ---------------------------------------------------------------------------
async function initializeZSMClient() {
  await configLoaded;

  const user = getUsername();
  if (!user) throw new Error('User identifier is empty.');

  if (!zsmAppConfig) {
    throw new Error('zsm_app_config.json failed to load.');
  }

  const needsNewClient = !umfaClient ||
    (umfaClient.config && umfaClient.config.consumer_id !== user);

  if (needsNewClient) {
    const clientConfig = { ...zsmAppConfig, consumer_id: user };
    console.log('[UMFA] Creating client with:', JSON.stringify(clientConfig, null, 2));
    umfaClient = new UMFAClient(clientConfig);
    await umfaClient.finished();
    console.log('[UMFA] Client ready, internal config:', JSON.stringify(umfaClient.config, null, 2));
  }

  return umfaClient;
}

// ---------------------------------------------------------------------------
// checkEnrollment
// ---------------------------------------------------------------------------
async function checkEnrollment(user, usePasskeysPlus = false) {
  console.log('[checkEnrollment] Input:', { user, usePasskeysPlus });
  try {
    let status;
    if (usePasskeysPlus) {
      status = await umfaClient.checkAllEnrollments(user);
    } else {
      status = await umfaClient.checkEnrollment(user);
    }
    const result = status instanceof Error ? false : status;
    console.log('[checkEnrollment] Result:', JSON.stringify(result, null, 2));
    return result;
  } catch (err) {
    console.error('[checkEnrollment] Error:', err);
    return false;
  }
}

// ---------------------------------------------------------------------------
// enroll
// ---------------------------------------------------------------------------
async function enroll(user, usingPasskeysPlus = false) {
  console.log('[enroll] Input:', { user, usingPasskeysPlus });
  const result = await umfaClient.enroll(user, usingPasskeysPlus);
  console.log('[enroll] SDK result:', result instanceof Error ? result.message : JSON.stringify(result, null, 2));

  // Already enrolled
  if (result === false) return false;

  // SDK error
  if (result instanceof Error) return result;

  // Validate token with server when we get a token object back
  if (result && typeof result === 'object') {
    await validateToken(user, result);
  }

  return result;
}

// ---------------------------------------------------------------------------
// authenticate
// ---------------------------------------------------------------------------
async function authenticate(user, usingPasskeysPlus = false) {
  console.log('[authenticate] Input:', { user, usingPasskeysPlus });
  let result;
  try {
    result = await umfaClient.authenticate(user, usingPasskeysPlus);
  } catch (err) {
    console.error('[authenticate] Exception:', err);
    return false;
  }
  console.log('[authenticate] SDK result:', result instanceof Error ? result.message : JSON.stringify(result, null, 2));

  // Not enrolled
  if (result === false) return false;

  // SDK error
  if (result instanceof Error) return false;

  // Empty object = MPC/crypto failure
  if (!result || (typeof result === 'object' && Object.keys(result).length === 0)) {
    console.log('[authenticate] Empty result — MPC/crypto failure');
    return false;
  }

  const credential = result?.credential ?? result;

  // Extract challenge data from response before stringify
  if (credential?.response) {
    try {
      const challenge = await hashSHA256(JSON.stringify(credential.response.clientDataJSON));
      const signedChallenge = JSON.stringify(credential.response.signature);
      updateChallengeDisplay(challenge, signedChallenge);
    } catch (err) {
      console.warn('[authenticate] Could not extract challenge data:', err.message);
    }
  }

  const output = JSON.stringify(credential);
  console.log('[authenticate] Output credential:', output.substring(0, 200) + (output.length > 200 ? '...' : ''));

  // Validate token with server
  if (credential && typeof credential === 'object') {
    await validateToken(user, credential);
  }

  return output;
}

// ---------------------------------------------------------------------------
// validateToken
// ---------------------------------------------------------------------------
async function validateToken(userId, token) {
  const requestBody = {
    application_id: zsmAppConfig.application_id,
    user_id: userId,
    token: token,
    environment: zsmAppConfig.application_environment
  };
  console.group('[validateToken]');
  console.log('User:', userId, '| URL:', zsmAppConfig.validate_url);
  try {
    const response = await fetch(zsmAppConfig.validate_url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${zsmAppConfig.server_key}`
      },
      body: JSON.stringify(requestBody)
    });
    const data = await response.json();
    console.log('Status:', response.status, response.ok ? 'OK' : 'FAIL');
    if (data.token) console.log('JWT present, length:', data.token.length);
    console.groupEnd();
    return response.ok;
  } catch (err) {
    console.error('Error:', err.message);
    console.groupEnd();
    return false;
  }
}

// ---------------------------------------------------------------------------
// showScreen — simple screen switcher
// ---------------------------------------------------------------------------
const SCREEN_ANNOUNCEMENTS = {
  'SETUP': 'Setup screen. Enter your user ID and trust this device.',
  'LOGIN': 'Login screen. Authenticate to continue.',
  'ACTIONS': 'Actions screen. You are logged in.'
};

function showScreen(screenId) {
  document.querySelectorAll('.screen').forEach(s => {
    s.classList.remove('active');
    s.setAttribute('aria-hidden', 'true');
  });
  const target = document.getElementById(screenId);
  if (target) {
    target.classList.add('active');
    target.setAttribute('aria-hidden', 'false');
  }

  // Username field is readonly on ACTIONS screen, editable otherwise
  const usernameEl = document.getElementById('username');
  usernameEl.readOnly = (screenId === 'ACTIONS');

  // Announce screen change to screen readers
  const announcer = document.getElementById('screen-announcer');
  if (announcer) announcer.textContent = SCREEN_ANNOUNCEMENTS[screenId] || '';
}

// ---------------------------------------------------------------------------
// updateUI — detect state and show correct screen + pills
// ---------------------------------------------------------------------------
async function updateUI() {
  const user = getUsername();

  // Check iShield credential (localStorage)
  const key = user ? FIDO2_STORAGE_PREFIX + user : null;
  const hasIShield = key && !!localStorage.getItem(key);

  // Check ZSM & Passkey status (SDK)
  let hasZSM = false;
  let hasPasskey = false;
  if (user) {
    try {
      await initializeZSMClient();
      const status = await checkEnrollment(user, true);
      if (status && !(status instanceof Error)) {
        hasZSM = status.hasZSMCred === true || !!status.zsmCredID;
        hasPasskey = status.hasRemotePasskey === true;
      }
    } catch (_) {}
  }

  // Update status pills
  function setPill(el, value) {
    el.textContent = value;
    const pill = el.closest('.pill');
    pill.classList.remove('pill-success', 'pill-danger', 'pill-neutral');
    if (value === 'true' || value === 'Active') pill.classList.add('pill-success');
    else if (value === 'false' || value === 'Suspended') pill.classList.add('pill-danger');
    else pill.classList.add('pill-neutral');
  }

  setPill(document.getElementById('ishield-status'), !user ? '--' : (hasIShield ? 'true' : 'false'));
  setPill(document.getElementById('zsm-status'), !user ? '--' : (hasZSM ? 'true' : 'false'));
  setPill(document.getElementById('passkey-status'), !user ? '--' : (hasPasskey ? 'true' : 'false'));

  // Passkeys+ pill
  const fullyEnrolled = hasIShield && hasZSM && hasPasskey;
  const suspended = isSuspended();
  const ppStatus = !user || !fullyEnrolled ? 'Not Enrolled' : (suspended ? 'Suspended' : 'Active');
  setPill(document.getElementById('passkeys-plus-status'), ppStatus);

  // Suspend button — enabled only when fully enrolled and not already suspended
  document.getElementById('suspend-device').disabled = !(fullyEnrolled && !suspended);

  // Restore Use Passkeys toggle state
  document.getElementById('actions-use-passkeys').checked = getPasskeysToggle();

  // Enable/disable Trust Device button
  document.getElementById('trust-device-btn').disabled = !user;

  // Login screen: toggle visibility and button text based on suspended state
  const toggleRow = document.querySelector('#LOGIN .toggle-row');
  const loginBtn = document.getElementById('login-btn');
  if (toggleRow) toggleRow.style.display = suspended ? 'none' : '';
  if (loginBtn) loginBtn.textContent = suspended ? 'Reactivate & Login' : 'Login';

  // Determine which screen to show
  if (hasZSM && hasPasskey) {
    // Device is trusted — show Login screen (or Actions if already logged in)
    if (STATE.loginID) {
      showScreen('ACTIONS');
    } else {
      showScreen('LOGIN');
    }
  } else {
    // No credentials — show Trust Device screen
    showScreen('SETUP');
  }
}

// ---------------------------------------------------------------------------
// trustDevice — enroll USB key then ZSM+Passkeys
// ---------------------------------------------------------------------------
async function trustDevice() {
  const user = getUsername();
  if (!user) return;

  const btn = document.getElementById('trust-device-btn');
  btn.classList.add('loading');
  btn.setAttribute('aria-busy', 'true');
  btn.setAttribute('aria-disabled', 'true');

  try {
    // Step 1: Enroll iShield USB key (raw WebAuthn)
    showFlash('flash-status', 'Insert your iShield USB key...', 'success');
    await webauthnEnroll(true); // silent — we handle flash messages

    // Verify enrollment succeeded (webauthnEnroll stores to localStorage)
    const key = FIDO2_STORAGE_PREFIX + user;
    if (!localStorage.getItem(key)) {
      showFlash('flash-status', 'iShield enrollment failed or cancelled', 'failure');
      return;
    }

    // Step 2: Show confirmation popup before ZSM enrollment
    const action = await showPopup("Now let's enroll with Passkeys+ (ZSM+Passkey)");
    if (action === 'cancel') {
      showFlash('flash-status', 'Passkeys+ enrollment cancelled', 'failure');
      await updateUI();
      return;
    }

    // Step 3: Enroll ZSM + Passkeys+
    showFlash('flash-status', 'Enrolling device with ZSM + Passkeys+...', 'success');
    await initializeZSMClient();
    const result = await enroll(user, true);

    if (!result || result === false || result instanceof Error) {
      showFlash('flash-status', 'ZSM enrollment failed', 'failure');
      await updateUI();
      return;
    }

    // Success — update state and show actions
    STATE.loginID = user;
    STATE.credentialsValid = true;
    STATE.token = result;
    showFlash('flash-status', 'Device trusted successfully', 'success');
    await updateUI();

  } catch (err) {
    console.error('[trustDevice] Error:', err);
    showFlash('flash-status', 'Trust Device failed', 'failure');
    await updateUI();
  } finally {
    btn.classList.remove('loading');
    btn.removeAttribute('aria-busy');
    btn.removeAttribute('aria-disabled');
  }
}

// ---------------------------------------------------------------------------
// login — authenticate with Passkeys+ only
// ---------------------------------------------------------------------------
async function login() {
  const user = getUsername();
  if (!user) return;

  const btn = document.getElementById('login-btn');
  btn.classList.add('loading');
  btn.setAttribute('aria-busy', 'true');
  btn.setAttribute('aria-disabled', 'true');

  try {
    // If suspended, require iShield + Passkeys+ to reactivate
    if (isSuspended()) {
      showFlash('flash-status', 'Device suspended — touch your iShield USB key to reactivate', 'success', 60000);
      const ok = await webauthnAuthenticate();
      if (!ok) return;

      showFlash('flash-status', 'Now authenticate with Passkeys+ to complete reactivation...', 'success');
      await initializeZSMClient();
      const reactivateCredential = await authenticate(user, true);
      if (!reactivateCredential || reactivateCredential instanceof Error) {
        showFlash('flash-status', 'Passkeys+ reactivation failed', 'failure');
        return;
      }

      setSuspended(false);
      setPasskeysToggle(true);
      STATE.loginID = user;
      STATE.credentialsValid = true;
      STATE.token = reactivateCredential;
      updateAuthIcons({ ishield: true, zsm: true, passkeys: true });
      await updateUI();
      showFlash('flash-status', 'Device reactivated', 'success');
      return;
    }

    const usePasskeys = document.getElementById('login-use-passkeys').checked;
    await initializeZSMClient();
    const credential = await authenticate(user, usePasskeys);

    if (!credential || credential instanceof Error) {
      showFlash('flash-status', 'Login failed', 'failure');
      return;
    }

    STATE.loginID = user;
    STATE.credentialsValid = true;
    STATE.token = credential;
    updateAuthIcons({ zsm: true, passkeys: usePasskeys });
    showScreen('ACTIONS');
  } catch (err) {
    console.error('[login] Error:', err);
    showFlash('flash-status', 'Login failed', 'failure');
  } finally {
    btn.classList.remove('loading');
    btn.removeAttribute('aria-busy');
    btn.removeAttribute('aria-disabled');
  }
}

// ---------------------------------------------------------------------------
// handleProtectedAction
// ---------------------------------------------------------------------------
async function handleProtectedAction(actionKey) {
  const actionLabel = PROTECTED_ACTION_LABELS[actionKey] ?? 'Protected Action';

  if (!STATE.loginID) {
    showFlash('action-status', `${actionLabel} Failed`, 'failure', 2000);
    return;
  }

  const usePasskeys = document.getElementById('actions-use-passkeys')?.checked === true;
  const credential = await authenticate(STATE.loginID, usePasskeys);

  if (!credential || credential instanceof Error) {
    showFlash('action-status', `${actionLabel} Failed`, 'failure', 2000);
  } else {
    updateAuthIcons({ zsm: true, passkeys: usePasskeys });
    showFlash('action-status', `${actionLabel} Authorized`, 'success', 2000);
  }
}

// ---------------------------------------------------------------------------
// logOut
// ---------------------------------------------------------------------------
function logOut() {
  umfaClient = null;
  STATE.reset();
  updateChallengeDisplay('--', '--');
  updateAuthIcons();
  showScreen('LOGIN');
}

// ---------------------------------------------------------------------------
// purgeStorage
// ---------------------------------------------------------------------------
function purgeStorage() {
  const username = getUsername();
  localStorage.clear();
  sessionStorage.clear();
  if (username) localStorage.setItem('username', username);
  try { indexedDB.deleteDatabase('ideem'); } catch (_) { /* ignore */ }
  window.location.reload();
}

// ---------------------------------------------------------------------------
// suspendDevice — suspend Passkeys+ login, require iShield re-auth
// ---------------------------------------------------------------------------
async function suspendDevice() {
  const user = getUsername();
  if (!user) return;

  const key = FIDO2_STORAGE_PREFIX + user;
  if (!localStorage.getItem(key)) return;
  if (isSuspended()) return;

  const action = await showPopup('Suspend Passkeys+ login? You will need your iShield USB key to reactivate.');
  if (action === 'cancel') return;

  setSuspended(true);
  logOut();
  await updateUI();
}

// ---------------------------------------------------------------------------
// DOMContentLoaded — wire up event listeners
// ---------------------------------------------------------------------------
document.addEventListener('DOMContentLoaded', () => {
  // Trust Device
  document.getElementById('trust-device-btn').addEventListener('click', () => trustDevice());

  // Login
  document.getElementById('login-btn').addEventListener('click', () => login());

  // Protected action buttons
  document.querySelectorAll('.btn-action').forEach((btn) => {
    btn.addEventListener('click', async (e) => {
      e.preventDefault();
      btn.classList.add('loading');
      btn.setAttribute('aria-busy', 'true');
      btn.setAttribute('aria-disabled', 'true');
      try {
        await handleProtectedAction(btn.dataset.action);
      } finally {
        btn.classList.remove('loading');
        btn.removeAttribute('aria-busy');
        btn.removeAttribute('aria-disabled');
      }
    });
  });

  // Persist Use Passkeys toggle state
  document.getElementById('actions-use-passkeys').addEventListener('change', (e) => {
    setPasskeysToggle(e.target.checked);
  });

  // Log Out
  document.getElementById('logout-btn').addEventListener('click', () => logOut());

  // Suspend Device
  document.getElementById('suspend-device').addEventListener('click', () => suspendDevice());

  // Reset Device
  document.getElementById('reset-device').addEventListener('click', () => purgeStorage());

  // Confirmation Popup buttons
  document.getElementById('popup-continue').addEventListener('click', () => hidePopup('continue'));
  document.getElementById('popup-cancel').addEventListener('click', () => hidePopup('cancel'));

  // Restore username from localStorage
  const savedUsername = localStorage.getItem('username');
  if (savedUsername) {
    document.getElementById('username').value = savedUsername;
  }

  // Persist username on input, update button state, and recheck enrollment status
  let usernameTimer = null;
  document.getElementById('username').addEventListener('input', (e) => {
    const user = getUsername();
    localStorage.setItem('username', user);
    document.getElementById('trust-device-btn').disabled = !user;

    if (usernameTimer) clearTimeout(usernameTimer);
    usernameTimer = setTimeout(() => updateUI(), 800);
  });

  // Copy button handlers
  document.querySelectorAll('.btn-copy').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      e.preventDefault();
      e.stopPropagation();
      const summary = btn.closest('summary');
      const details = summary?.closest('details');
      const pre = details?.querySelector('.challenge-full');
      const text = pre?.textContent;
      if (text) {
        try {
          await navigator.clipboard.writeText(text);
          const originalHTML = btn.innerHTML;
          btn.textContent = '✓';
          btn.style.opacity = '1';
          btn.style.color = 'var(--color-terminal-value)';
          setTimeout(() => {
            btn.innerHTML = originalHTML;
            btn.style.opacity = '';
            btn.style.color = '';
          }, 1500);
        } catch (err) {
          console.error('Copy failed:', err);
        }
      }
    });
  });

  // Detect existing credentials and show correct screen
  updateUI();
});
