/**
 * app.js -- Demo Orchestration & UI
 *
 * This is the application glue layer. It imports the two integration
 * modules (ishield.js and umfa.js) and wires them to the UI.
 *
 * A partner integrating iShield + Passkeys+ into their own app would
 * primarily study ishield.js and umfa.js. This file is demo-specific
 * and handles screens, flash messages, popups, and event listeners.
 *
 * FLOW:
 *   1. Trust Device  -- webauthnEnroll() then enroll() with Passkeys+
 *   2. Login         -- authenticate() with Passkeys+ (no USB key needed)
 *   3. Actions       -- step-up authenticate() per protected action
 *   4. Suspend       -- flag device as suspended, require iShield to reactivate
 *
 * NOTE: state.js is loaded as a classic script (non-module) so that the
 * State class is available as a global. The stateChange custom events it
 * dispatches are available but unused in this demo.
 */

import {
  hasStoredCredential,
  isSuspended,
  setSuspended,
  getPasskeysToggle,
  setPasskeysToggle,
  webauthnEnroll,
  webauthnAuthenticate
} from './ishield.js';

import {
  initializeZSMClient,
  checkAllEnrollment,
  enroll,
  authenticate,
  resetClient
} from './umfa.js';

// ---------------------------------------------------------------------------
// Shared UI helpers
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
// Challenge display helpers (UI-only -- not called from ishield.js or umfa.js)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------
const STATE = new State({
  loginID: null
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
  const hasIShield = user ? hasStoredCredential(user) : false;

  // Check ZSM & Passkey status (SDK)
  let hasZSM = false;
  let hasPasskey = false;
  if (user) {
    try {
      await initializeZSMClient(user);
      const status = await checkAllEnrollment(user);
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
  const suspended = isSuspended(user);
  const ppStatus = !user || !fullyEnrolled ? 'Not Enrolled' : (suspended ? 'Suspended' : 'Active');
  setPill(document.getElementById('passkeys-plus-status'), ppStatus);

  // Suspend button — enabled only when fully enrolled and not already suspended
  document.getElementById('suspend-device').disabled = !(fullyEnrolled && !suspended);

  // Restore Use Passkeys toggle state
  document.getElementById('actions-use-passkeys').checked = getPasskeysToggle(user);

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
    try {
      await webauthnEnroll(user);
    } catch (err) {
      showFlash('flash-status',
        err.name === 'NotAllowedError' ? 'Cancelled or timed out' :
        err.name === 'SecurityError' ? 'Security error — try HTTPS or localhost' :
        err.name === 'InvalidStateError' ? 'Key already registered for this user' :
        err.message || 'iShield enrollment failed',
        'failure'
      );
      return;
    }

    // Verify enrollment succeeded (webauthnEnroll stores to localStorage)
    if (!hasStoredCredential(user)) {
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
    await initializeZSMClient(user);
    const result = await enroll(user, true);

    if (!result || result === false || result instanceof Error) {
      showFlash('flash-status', 'ZSM enrollment failed', 'failure');
      await updateUI();
      return;
    }

    // Success — update state and show actions
    STATE.loginID = user;
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
    if (isSuspended(user)) {
      showFlash('flash-status', 'Device suspended — touch your iShield USB key to reactivate', 'success', 60000);

      const ishieldResult = await webauthnAuthenticate(user);
      if (!ishieldResult.success) {
        if (ishieldResult.error?.name === 'NotAllowedError') {
          showFlash('flash-status', 'Cancelled or timed out', 'failure');
        } else {
          showFlash('flash-status', ishieldResult.error?.message || 'Authentication failed', 'failure');
        }
        return;
      }
      updateIShieldChallengeDisplay(ishieldResult.clientDataHash, ishieldResult.signatureHex);

      showFlash('flash-status', 'Now authenticate with Passkeys+ to complete reactivation...', 'success');
      await initializeZSMClient(user);
      const reactivateResult = await authenticate(user, true);
      if (!reactivateResult.success) {
        showFlash('flash-status', 'Passkeys+ reactivation failed', 'failure');
        return;
      }

      if (reactivateResult.challengeData) {
        updateChallengeDisplay(reactivateResult.challengeData.challenge, reactivateResult.challengeData.signedChallenge);
      }

      setSuspended(user, false);
      setPasskeysToggle(user, true);
      STATE.loginID = user;
      updateAuthIcons({ ishield: true, zsm: true, passkeys: true });
      await updateUI();
      showFlash('flash-status', 'Device reactivated', 'success');
      return;
    }

    const usePasskeys = document.getElementById('login-use-passkeys').checked;
    await initializeZSMClient(user);
    const authResult = await authenticate(user, usePasskeys);

    if (!authResult.success) {
      showFlash('flash-status', 'Login failed', 'failure');
      return;
    }

    if (authResult.challengeData) {
      updateChallengeDisplay(authResult.challengeData.challenge, authResult.challengeData.signedChallenge);
    }

    STATE.loginID = user;
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
  const authResult = await authenticate(STATE.loginID, usePasskeys);

  if (!authResult.success) {
    showFlash('action-status', `${actionLabel} Failed`, 'failure', 2000);
  } else {
    if (authResult.challengeData) {
      updateChallengeDisplay(authResult.challengeData.challenge, authResult.challengeData.signedChallenge);
    }
    updateAuthIcons({ zsm: true, passkeys: usePasskeys });
    showFlash('action-status', `${actionLabel} Authorized`, 'success', 2000);
  }
}

// ---------------------------------------------------------------------------
// logOut
// ---------------------------------------------------------------------------
function logOut() {
  resetClient();
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

  if (!hasStoredCredential(user)) return;
  if (isSuspended(user)) return;

  const action = await showPopup('Suspend Passkeys+ login? You will need your iShield USB key to reactivate.');
  if (action === 'cancel') return;

  setSuspended(user, true);
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
    setPasskeysToggle(getUsername(), e.target.checked);
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
