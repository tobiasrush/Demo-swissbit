# Demo-swissbit: iShield USB Key + Ideem ZSM WebAuthn Demo

## Reference Projects Analyzed

| Project | Path | What was extracted |
|---------|------|--------------------|
| **ideem-login-phone** | `/Users/tobyrush/Documents/GitHub/ideem-login-phone/` | SDK integration patterns, Vercel deployment strategy (importmap + vendor), build.js, state.js, ZSM config, enrollment/auth decision tree, token validation flow, popup pattern, protected actions |
| **ideem-implement-demo** | `/Users/tobyrush/Documents/GitHub/ideem-implement-demo/` | Alternative Vite-based approach (not used), simpler app.js structure, hardcoded config pattern |
| **ideem-implement-demo-server** | `/Users/tobyrush/Documents/GitHub/ideem-implement-demo-server/` | Express backend token validation pattern (not used — this demo is client-side only) |

Key files read line-by-line:
- `ideem-login-phone/umfa.js` (1,484 lines) — all SDK integration logic
- `ideem-login-phone/samples.js` (944 lines) — UI helpers, state management, debug toolbar
- `ideem-login-phone/state.js` (75 lines) — reactive State class
- `ideem-login-phone/build.js` (111 lines) — vendor copy script
- `ideem-login-phone/umfa.html` (157 lines) — HTML structure
- `ideem-login-phone/package.json`, `vercel.json`, `zsm_app_config.json`
- `ideem-implement-demo/app.js`, `index.html`, `package.json`
- `ideem-implement-demo-server/index.js`, `package.json`

---

## Context

Swissbit makes a USB security key called iShield. This demo app tests the iShield for WebAuthn alongside Ideem's ZSM (Zero-Knowledge Secure Module). It's a static vanilla JS web app that deploys to Vercel, following the proven patterns from `ideem-login-phone`.

The app supports: login via ZSM + optional Passkeys+, enrollment popup for new devices, and step-up authentication for protected actions (payments, transfers, etc.).

**Location:** `/Users/tobyrush/Documents/GitHub/Demo-swissbit/` (currently empty)

---

## Critical Architecture Pattern (Vercel)

Vercel doesn't serve `node_modules/` as static files. The solution:

1. `npm install` pulls `@ideem/zsm-client-sdk` and `@ideem/plugins.passkeys-plus` into `node_modules/`
2. `postinstall` triggers `build.js` which copies specific SDK `.js` files to `vendor/@ideem/`
3. HTML uses `<script type="importmap">` to map bare specifiers to `./vendor/` paths
4. Vercel serves the `vendor/` directory as static files

---

## Files to Create (9 total)

### 1. `package.json`

```json
{
  "name": "demo-swissbit",
  "private": true,
  "type": "module",
  "scripts": {
    "build": "node build.js",
    "postinstall": "npm run build"
  },
  "dependencies": {
    "@ideem/plugins.passkeys-plus": "^1.2.1",
    "@ideem/zsm-client-sdk": "^2.7.0"
  }
}
```

### 2. `build.js` — Copy exactly from `ideem-login-phone/build.js`

This 111-line script copies 17 files from `node_modules/@ideem/zsm-client-sdk/` and 10 files from `node_modules/@ideem/plugins.passkeys-plus/` to `vendor/@ideem/`. The exact file lists are in the script.

**zsm-client-sdk files:** ErrorHandler.js, EventCoordinator.js, FIDO2Client.js, FIDO2ClientBase.js, GlobalScoping.js, IdentityIndexing.js, PluginManager.js, RelyingParty.js, RelyingPartyBase.js, UMFAClient.js, UMFAClientBase.js, Utils.js, WASMRustInterface.js (2.4MB WASM), WebAuthnClient.js, WebAuthnClientBase.js, ZSMClientSDK.js, LICENSE, README.md, CHANGELOG.md

**plugins.passkeys-plus files:** FIDO2Client.js, PKPUtils.js, PasskeysPlusClient.js, PasskeysPlus.js, RelyingParty.js, UMFAClient.js, WebAuthnClient.js, LICENSE, README.md, CHANGELOG.md

### 3. `vercel.json`

```json
{
  "buildCommand": "npm run build",
  "outputDirectory": ".",
  "installCommand": "npm install"
}
```

### 4. `.gitignore`

```
node_modules/
/vendor
.env*
.vercel
.DS_Store
npm-debug.log*
```

### 5. `zsm_app_config.json`

```json
{
  "application_id": "5a753520-5364-4a32-9bdf-d1ffc51e8f6b",
  "api_key": "5156c77a-4a05-3cf2-b368-ac718411eab3",
  "server_key": "71394918-6099-4996-a600-bbfbd0b6d88c",
  "validate_url": "https://zsm-authenticator-demo.useideem.com/api/pkp/validate-token",
  "region": "demo"
}
```

### 6. `state.js` — Copy exactly from `ideem-login-phone/state.js`

75-line Proxy-based reactive State class. Dispatches `stateChange` CustomEvents on mutation. Has `reset()` method. No modifications needed.

### 7. `index.html` — New file

Key requirements:

**Importmap in `<head>`:**
```html
<script type="importmap">
{
  "imports": {
    "@ideem/zsm-client-sdk": "./vendor/@ideem/zsm-client-sdk/ZSMClientSDK.js",
    "@ideem/zsm-client-sdk/": "./vendor/@ideem/zsm-client-sdk/",
    "@ideem/plugins.passkeys-plus": "./vendor/@ideem/plugins.passkeys-plus/PasskeysPlus.js",
    "@ideem/plugins.passkeys-plus/": "./vendor/@ideem/plugins.passkeys-plus/"
  }
}
</script>
```

**Script loading order:**
- `<script src="./state.js"></script>` (non-module, defines global `State` class)
- `<script type="module" src="./app.js"></script>` (module, uses `State`)

**UI structure:**

- **Header:** Dual branding (Swissbit + Ideem logos), title "iShield Key + ZSM", subtitle "Hardware WebAuthn Demo"
- **LOGIN screen** (`.screen.active`, id=`LOGIN`):
  - Form `#login-form` with `onsubmit="return false"`
  - Input `#username` (text, autocomplete off)
  - Toggle/checkbox `#use-passkeys` for Passkeys+
  - Submit button `#login-btn`
- **LOGGED_IN screen** (`.screen`, id=`LOGGED_IN`):
  - Welcome message with `#display-name` span
  - Subtitle referencing iShield key for step-up auth
  - 4 action buttons with `data-action` attributes: `make-payment`, `transfer-money`, `change-setting`, `add-beneficiary`
  - `#action-status` div for success/failure flash
  - `#logout-btn`
- **Enrollment popup overlay** (`#enrollment-popup`, initially `display: none`):
  - `#popup-message` paragraph
  - `#popup-passkey-option` div (conditionally shown) with `#popup-use-passkeys` checkbox
  - Instructions text referencing "iShield USB key"
  - `#popup-cancel` and `#popup-enroll` buttons
- **Footer:**
  - Status pills: `ZSM: <b id="zsm-bound">--</b>` and `Passkey: <b id="passkey-server">--</b>`
  - `#reset-device` button

### 8. `style.css` — New file

Design specs:
- Dark navy primary (`#1a1f36`), amber accent (`#e8a028`), light gray background (`#f5f5f7`)
- Centered card layout, `max-width: 480px`, no phone frame
- CSS toggle switch for passkeys (not a bare checkbox)
- 2x2 grid for protected action buttons (`.action-grid`)
- Popup overlay with semi-transparent backdrop (`rgba(0,0,0,0.5)`)
- Screen transitions: `.screen { display: none }` / `.screen.active { display: block }`
- Action status flash: green `.success` background, red `.failure` background (auto-clears after 2s)
- Status pills in footer: small, muted text
- Responsive, works on desktop and mobile

### 9. `app.js` — New file (~280 lines, simplified from 1,484-line umfa.js)

**Imports:**
```javascript
import { UMFAClient } from '@ideem/zsm-client-sdk';
import PasskeysPlus from '@ideem/plugins.passkeys-plus';
```

**State initialization:**
```javascript
const STATE = new State({
  activeCard: 'LOGIN',
  loginID: null,
  credentialsValid: false,
  token: null,
  lastAuthUsedPasskeys: false,
  hasPasskeysCredential: false
});
```

**State change listener:**
```javascript
document.addEventListener('stateChange', (e) => {
  const { key, value } = e.detail;
  if (key === 'activeCard') screenTransition(value);
  updateStatusPills();
});
```

**Config loading:**
```javascript
let zsmAppConfig = null;
let umfaClient = null;

const configLoaded = fetch('./zsm_app_config.json')
  .then(res => res.json())
  .then(config => { zsmAppConfig = config; });
```

**Core functions:**

#### `initializeZSMClient()`
- Awaits `configLoaded`
- Gets username from `#username` input
- Only creates new client if `umfaClient` is null or `consumer_id` changed
- `umfaClient = new UMFAClient({ ...zsmAppConfig, consumer_id: user })`
- `await umfaClient.finished()` (waits for WASM)

#### `checkEnrollment(user, usePasskeysPlus)`
- If `usePasskeysPlus`: calls `umfaClient.checkAllEnrollments(user)`
  - Returns object: `{ hasZSMCred, zsmCredID, hasRemotePasskey, hasLocalPasskey, hasPKPCred }`
- Else: calls `umfaClient.checkEnrollment(user)`
- Returns `false` if Error

#### `enroll(user, usingPasskeysPlus)`
- Calls `umfaClient.enroll(user, usingPasskeysPlus)`
- Returns `false` if already enrolled
- Returns Error on failure
- On success: calls `validateToken(user, result)` if result is an object
- Returns the enrollment token

#### `authenticate(user, usingPasskeysPlus)`
- Calls `umfaClient.authenticate(user, usingPasskeysPlus)`
- Checks for `false` (not enrolled), `Error`, empty object `{}` (MPC failure)
- Extracts credential: `result?.credential ?? result`
- Returns `JSON.stringify(credential)`

#### `validateToken(userId, token)`
```javascript
fetch(zsmAppConfig.validate_url, {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${zsmAppConfig.server_key}`
  },
  body: JSON.stringify({
    application_id: zsmAppConfig.application_id,
    user_id: userId,
    token: token
  })
});
```

#### `performLogin(usingPasskeysPlus)` — Main decision tree
1. Init ZSM client
2. Check enrollment (always with `usePasskeysPlus=true` for full status)
3. Determine `hasLocalZSM`:
   ```javascript
   const hasLocalZSM = localZSMStatus !== false &&
     localZSMStatus !== null &&
     !(localZSMStatus instanceof Error) &&
     (localZSMStatus.hasZSMCred === true || !!localZSMStatus.zsmCredID);
   ```
4. Determine `hasRemotePasskey`:
   ```javascript
   const hasRemotePasskey = localZSMStatus &&
     !(localZSMStatus instanceof Error) &&
     localZSMStatus.hasRemotePasskey === true;
   ```
5. **If hasLocalZSM:**
   - If user wants passkeys AND no remote passkey: show confirmation popup, then `enroll(user, true)` to add passkeys
   - Else: `authenticate(user, usingPasskeysPlus)`
6. **If NOT hasLocalZSM:**
   - Show enrollment popup (with passkey checkbox if `hasRemotePasskey`)
   - `enrollWithPasskeys = hasRemotePasskey ? popupResult.usePasskeys : usingPasskeysPlus`
   - `enroll(user, enrollWithPasskeys)`
7. On success: update STATE (`loginID`, `credentialsValid`, `activeCard='LOGGED_IN'`, etc.)
8. Re-check enrollment for status pills

#### `handleProtectedAction(actionKey, usingPasskeysPlus)`
- Action labels: `make-payment` → "Make Payment", `transfer-money` → "Transfer Money", `change-setting` → "Change Setting", `add-beneficiary` → "Add Beneficiary"
- Re-authenticates via `authenticate(STATE.loginID, usingPasskeysPlus)`
- Shows success/failure flash in `#action-status` (auto-clears after 2s)

#### `showEnrollmentPopup(message, showPasskeyCheckbox, confirmLabel)`
- Returns `Promise<{action: 'enroll'|'cancel', usePasskeys: boolean}>`
- Sets `#popup-message` text, shows/hides `#popup-passkey-option`, sets button label
- Shows `#enrollment-popup` with `display: flex`
- Stores `resolve` function in module-level `popupResolve`

#### `hideEnrollmentPopup(action)`
- Reads `#popup-use-passkeys` checked state
- Hides popup, resolves promise with `{ action, usePasskeys }`

#### `logOut()`
- Nulls `umfaClient`
- Preserves `loginID`, resets rest of STATE
- Re-checks enrollment after 200ms delay

#### `purgeStorage()`
- Preserves username from input field
- `localStorage.clear()`, `sessionStorage.clear()`
- `indexedDB.deleteDatabase('ideem')`
- `window.location.reload()`

#### `screenTransition(targetId)`
- Removes `.active` from current `.screen.active`
- Adds `.active` to target element
- Updates `#display-name` if transitioning to LOGGED_IN

#### `updateStatusPills(enrollmentStatus)`
- Updates `#zsm-bound` text: `true` if `hasZSMCred || zsmCredID`
- Updates `#passkey-server` text: `true` if `hasRemotePasskey`
- Shows `false` / `--` when no status

**DOMContentLoaded setup:**
- `#login-form` submit → `performLogin(checked)`
- `.btn-action` click → `handleProtectedAction(dataset.action, STATE.lastAuthUsedPasskeys)`
- `#logout-btn` click → `logOut()`
- `#reset-device` click → `purgeStorage()`
- `#popup-enroll` click → `hideEnrollmentPopup('enroll')`
- `#popup-cancel` click → `hideEnrollmentPopup('cancel')`
- Restore username from `localStorage.getItem('username')`
- `#username` input event → `localStorage.setItem('username', value)`

**Window load event (with 500ms delay):**
- `checkEnrollmentOnLoad()` — inits client if username exists, calls `checkAllEnrollments`, updates pills

### 10. Logo files
- Copy `ideem-login-phone/Ideem_logo.png` → `ideem-logo.png`
- Create simple SVG placeholder for `swissbit-logo.svg` (replace with real logo later)

---

## What Was Removed vs ideem-login-phone

- Debug toolbar and all debug mode logic
- Transcript logging (`traceToTranscript`, `oneTimeTraceToTranscript`)
- Console overrides (`console.l`, `console.e`, `console.verbose`, `console.end`)
- Phone frame UI wrapper
- Region switching and multi-region config
- Alipay branding and credentials
- Password field (not needed for WebAuthn)
- Retry logic for credentialID errors
- SHA-256 hash display of challenges
- Status queue animation system
- Menu system and admin toggles
- Test automation hooks (`window._debugLastError`, `debugStep`, `debugResult`)
- `window.debugAPI` exports

## What Was Preserved

- Full enrollment check → enroll/authenticate decision tree from `performUMFASecondFactor()`
- Token validation POST with Bearer auth
- Promise-based enrollment popup pattern
- Reactive State class with `stateChange` events
- Username persistence in localStorage
- IndexedDB cleanup on device reset
- WASM initialization via `umfaClient.finished()`
- `consumer_id` change detection for client reuse

---

## Verification Steps

1. `npm install` completes without errors and `vendor/@ideem/` is populated with SDK files
2. `python3 -m http.server 8000` — login screen renders with dual branding
3. Enter a user ID, click Log In → enrollment popup appears (first time on device)
4. Click Enroll → browser prompts for iShield USB key (WebAuthn ceremony)
5. After enrollment, LOGGED_IN screen shows with 4 protected action buttons
6. Click a protected action → step-up auth triggers iShield key prompt again
7. Footer status pills update correctly (ZSM: true, Passkey: depends on toggle)
8. Log Out returns to login screen, enrollment status refreshes in footer
9. Reset Device clears IndexedDB + localStorage, page reloads clean

---

## Suggested Work Split (Claude + Codex)

| Agent | Files | Rationale |
|-------|-------|-----------|
| **Codex** | `index.html`, `style.css` | Pure HTML/CSS, no SDK knowledge needed. All element IDs and class names are specified above. |
| **Claude** | `app.js` | Requires deep understanding of SDK enrollment/auth decision tree, error handling, token validation. |
| **Either** | `package.json`, `build.js` (copy), `vercel.json` (copy), `state.js` (copy), `.gitignore`, `zsm_app_config.json`, logos | Simple configs and direct copies. |
