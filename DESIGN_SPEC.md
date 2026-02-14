# Demo-swissbit: Banking/Fintech Design Spec

> **Purpose:** This document is a comprehensive implementation guide for a frontend-developer agent. It specifies every CSS change needed to transform the current iShield Key + ZSM demo into a polished banking/fintech interface.

---

## Table of Contents

1. [Design Philosophy](#1-design-philosophy)
2. [Color Palette](#2-color-palette)
3. [Typography](#3-typography)
4. [Spacing System](#4-spacing-system)
5. [Component-by-Component Redesign](#5-component-by-component-redesign)
6. [Responsive Breakpoints](#6-responsive-breakpoints)
7. [HTML Changes](#7-html-changes)
8. [Animation & Transitions](#8-animation--transitions)
9. [Implementation Checklist](#9-implementation-checklist)

---

## 1. Design Philosophy

- **Trust-forward:** Navy/slate tones convey security. No bright saturated colors except for intentional accents.
- **Minimal & clean:** Generous whitespace, restrained color use, no visual clutter.
- **Technical credibility:** Challenge/crypto sections use a dark terminal aesthetic -- dark background, monospace font, subtle green/cyan accents -- reinforcing that real cryptographic operations are happening.
- **Modern banking feel:** Think Revolut, Wise, Mercury -- flat cards with subtle shadows, refined button states, polished micro-interactions.

---

## 2. Color Palette

Replace all existing CSS custom properties in `:root`. Every color below is specified as a hex value.

```css
:root {
  /* === Primary === */
  --color-primary:        #0f2b46;   /* Deep navy -- headings, primary buttons, key text */
  --color-primary-light:  #1a3d5c;   /* Lighter navy -- hover states, secondary emphasis */
  --color-primary-muted:  #3a5a7c;   /* Muted blue-slate -- labels, secondary text */

  /* === Accent === */
  --color-accent:         #0d7c66;   /* Deep teal -- toggle on-state, success-adjacent actions */
  --color-accent-light:   #10a37f;   /* Brighter teal -- hover accent, links */
  --color-accent-bg:      #e8f5f1;   /* Very light teal tint -- accent backgrounds */

  /* === Backgrounds === */
  --color-bg:             #f0f2f5;   /* Cool gray page background */
  --color-bg-warm:        #f7f8fa;   /* Slightly warmer gray -- card hover, alt sections */
  --color-white:          #ffffff;   /* Card backgrounds */

  /* === Text === */
  --color-text:           #1e293b;   /* Slate-900 -- primary body text */
  --color-text-secondary: #64748b;   /* Slate-500 -- secondary/muted text */
  --color-text-tertiary:  #94a3b8;   /* Slate-400 -- placeholders, disabled text */

  /* === Borders === */
  --color-border:         #e2e8f0;   /* Slate-200 -- standard borders */
  --color-border-strong:  #cbd5e1;   /* Slate-300 -- emphasized borders */

  /* === Status === */
  --color-success:        #059669;   /* Emerald-600 -- success messages */
  --color-success-bg:     #ecfdf5;   /* Emerald-50 -- success background */
  --color-danger:         #dc2626;   /* Red-600 -- danger/destructive */
  --color-danger-bg:      #fef2f2;   /* Red-50 -- danger background */
  --color-warning:        #d97706;   /* Amber-600 -- warning/caution */
  --color-warning-bg:     #fffbeb;   /* Amber-50 -- warning background */

  /* === Terminal/Code === */
  --color-terminal-bg:    #0f172a;   /* Slate-900 -- terminal background */
  --color-terminal-text:  #e2e8f0;   /* Slate-200 -- terminal body text */
  --color-terminal-label: #38bdf8;   /* Sky-400 -- terminal labels/keys */
  --color-terminal-value: #4ade80;   /* Green-400 -- terminal values */
  --color-terminal-border:#1e293b;   /* Slate-800 -- terminal section borders */
  --color-terminal-summary:#94a3b8;  /* Slate-400 -- summary text in terminal */

  /* === Shadows === */
  --shadow-sm:   0 1px 2px rgba(15, 43, 70, 0.05);
  --shadow-md:   0 4px 12px rgba(15, 43, 70, 0.08);
  --shadow-lg:   0 8px 30px rgba(15, 43, 70, 0.12);
  --shadow-card: 0 1px 3px rgba(15, 43, 70, 0.06), 0 8px 24px rgba(15, 43, 70, 0.08);

  /* === Radii === */
  --radius-xs:  4px;
  --radius-sm:  6px;
  --radius-md:  10px;
  --radius-lg:  14px;
  --radius-xl:  20px;
  --radius-pill: 9999px;
}
```

### Rationale

| Current | New | Why |
|---------|-----|-----|
| `--color-primary: #1a1f36` (near-black) | `#0f2b46` (deep navy) | Warmer, more distinctly blue -- reads as "banking" rather than "generic dark" |
| `--color-accent: #e8a028` (gold/amber) | `#0d7c66` (deep teal) | Teal is the dominant accent in modern fintech (Wise, Mercury). Gold felt promotional. |
| `--color-bg: #f5f5f7` (warm gray) | `#f0f2f5` (cool gray) | Cooler tone pairs better with navy primary |
| Flat shadow | Layered `shadow-card` | Double-layer shadows feel more refined and dimensional |

---

## 3. Typography

### Font Stack

Keep the system font stack but add Inter as a preferred web font. The implementation should add a Google Fonts import for Inter at the top of the CSS file.

```css
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');

body {
  font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
}
```

### Monospace Stack (for terminal/code sections)

```css
--font-mono: 'SF Mono', 'Fira Code', 'Cascadia Code', 'JetBrains Mono', Menlo, Monaco, Consolas, monospace;
```

### Type Scale

All sizes in `rem` (base 16px). Line heights specified per level.

| Token / Usage | Size | Weight | Line Height | Letter Spacing |
|---------------|------|--------|-------------|----------------|
| `h1` (page title) | `1.375rem` (22px) | 700 | 1.3 | `-0.02em` |
| `.subtitle` | `0.8125rem` (13px) | 400 | 1.4 | `0.02em` |
| Body text / labels | `0.875rem` (14px) | 500 | 1.5 | `0` |
| Input text | `0.9375rem` (15px) | 400 | 1.5 | `0` |
| Button text (primary) | `0.9375rem` (15px) | 600 | 1 | `0.01em` |
| Button text (action grid) | `0.8125rem` (13px) | 600 | 1.2 | `0.01em` |
| Button text (small/footer) | `0.75rem` (12px) | 500 | 1 | `0.02em` |
| Pill text | `0.6875rem` (11px) | 500 | 1 | `0.02em` |
| Terminal/code text | `0.75rem` (12px) | 400 | 1.5 | `0` |
| Terminal labels | `0.6875rem` (11px) | 600 | 1.3 | `0.03em` |
| Challenge section label | `0.75rem` (12px) | 700 | 1.3 | `0.04em` |

### Key Typography Changes from Current

- Title `h1`: Decrease from `1.5rem` to `1.375rem` -- tighter, more refined
- Subtitle: Add `text-transform: uppercase` and `letter-spacing: 0.02em` for a professional badge feel
- All labels: Bump to `font-weight: 500` minimum (current uses mix of 400/500/600)
- Challenge section labels: Add `text-transform: uppercase` and wide letter-spacing for a terminal/HUD feel

---

## 4. Spacing System

Use a consistent 4px-based spacing scale. Define these as variables or use directly:

| Token | Value | Usage |
|-------|-------|-------|
| `--space-1` | `4px` | Tight gaps (icon-to-text) |
| `--space-2` | `8px` | Small gaps (pill padding, inner gaps) |
| `--space-3` | `12px` | Standard element gaps |
| `--space-4` | `16px` | Section separators, button margin |
| `--space-5` | `20px` | Card internal top/bottom padding delta |
| `--space-6` | `24px` | Card horizontal padding, section spacing |
| `--space-8` | `32px` | Card vertical padding, major section breaks |
| `--space-10` | `40px` | Page-level spacing |

### Key Spacing Changes

| Element | Current | New |
|---------|---------|-----|
| Card padding | `32px 28px` | `32px 28px` (desktop), `24px 20px` (mobile) -- keep current |
| Username row margin-bottom | `4px` | `20px` -- needs breathing room below |
| Toggle row margin | `16px 0` | `20px 0` -- more vertical rhythm |
| Action grid gap | `12px` | `10px` -- slightly tighter |
| Action grid margin-bottom | `16px` | `20px` |
| Status pills margin-top | `20px` | `24px` |
| Status pills margin-bottom | `12px` | `4px` -- less space before flash |
| Challenge display margin-top | `16px` | `24px` -- more separation from buttons |
| Footer margin-top | `24px` | `20px` |
| Body padding | `24px 16px` | `32px 16px` (desktop), `20px 12px` (mobile) |

---

## 5. Component-by-Component Redesign

### 5.1 Header

**Current state:** Centered logos with a `1px` divider, large bold title, plain subtitle.

**New design:**

```css
.header {
  text-align: center;
  margin-bottom: 28px;      /* was 24px */
  max-width: 480px;
  width: 100%;
}

.logo-row {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 14px;                 /* was 16px -- slightly tighter */
  margin-bottom: 20px;       /* was 16px */
}

.logo {
  height: 36px;              /* was 40px -- more refined */
  object-fit: contain;
}

.logo-swissbit {
  height: 32px;              /* was 36px */
}

.logo-divider {
  width: 1px;
  height: 28px;              /* was 32px */
  background: var(--color-border-strong); /* stronger than current --color-border */
}

.header h1 {
  font-size: 1.375rem;       /* was 1.5rem */
  font-weight: 700;
  color: var(--color-primary);
  margin-bottom: 4px;
  letter-spacing: -0.02em;   /* NEW: tight tracking for modern feel */
}

.subtitle {
  font-size: 0.8125rem;      /* was 0.9rem */
  color: var(--color-text-secondary); /* was --color-muted */
  font-weight: 400;
  text-transform: uppercase;  /* NEW */
  letter-spacing: 0.08em;     /* NEW: wide-tracked uppercase */
}
```

**HTML change required:** Swap `swissbit-logo.svg` to `swissbit_logo.png` in the `<img>` src attribute.

---

### 5.2 Card Container

**Current state:** White card with `12px` radius and single-layer shadow.

**New design:**

```css
.card {
  background: var(--color-white);
  border-radius: var(--radius-lg);    /* was --radius (12px), now 14px */
  box-shadow: var(--shadow-card);     /* was --shadow -- now double-layer */
  max-width: 480px;
  width: 100%;
  padding: 32px 28px;                 /* unchanged */
  border: 1px solid var(--color-border); /* NEW: subtle border for definition */
}
```

The added `border` gives the card a crisper edge on light backgrounds, common in banking UIs.

---

### 5.3 Username Row

**Current state:** Horizontal flex with label and input, `4px` bottom margin.

**New design -- editable state:**

```css
.username-row {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 20px;               /* was 4px -- much more breathing room */
}

.username-row label {
  font-size: 0.8125rem;              /* was 0.85rem */
  font-weight: 600;
  color: var(--color-primary-muted);  /* was --color-primary -- softer */
  white-space: nowrap;
  text-transform: uppercase;          /* NEW */
  letter-spacing: 0.04em;             /* NEW */
}

#username {
  flex: 1;
  padding: 10px 14px;                /* was 12px 14px -- slightly tighter */
  border: 1.5px solid var(--color-border-strong); /* was 1px solid --color-border */
  border-radius: var(--radius-sm);    /* now 6px instead of 8px */
  font-size: 0.9375rem;              /* was 1rem */
  font-weight: 400;
  color: var(--color-text);
  outline: none;
  transition: border-color 0.2s, box-shadow 0.2s; /* add box-shadow transition */
  background: var(--color-white);
}

#username::placeholder {
  color: var(--color-text-tertiary);  /* NEW explicit placeholder color */
}

#username:focus {
  border-color: var(--color-accent);  /* teal instead of gold */
  box-shadow: 0 0 0 3px var(--color-accent-bg); /* NEW: focus ring */
}
```

**Readonly state (ACTIONS screen):**

```css
#username[readonly] {
  border: none;
  background: transparent;
  padding-left: 0;
  cursor: default;
  color: var(--color-primary);
  font-weight: 700;                   /* was 600 -- bolder for "logged in as" feel */
  font-size: 1.0625rem;              /* NEW: slightly larger when displaying the username */
  margin-bottom: 0;
}
#username[readonly]:focus {
  border-color: transparent;
  box-shadow: none;                   /* NEW: no focus ring when readonly */
}
```

---

### 5.4 Auth Icons Row

**Current state:** `20px` height icons inline.

**New design:**

```css
.auth-icon {
  height: 18px;                       /* was 20px -- slightly smaller */
  object-fit: contain;
  opacity: 0.8;                       /* NEW: subtle dimming */
  transition: opacity 0.2s;
}
```

No other changes needed -- these are small inline indicators.

---

### 5.5 Buttons

#### 5.5.1 Base Button

```css
.btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  border: none;
  border-radius: var(--radius-sm);    /* now 6px */
  font-size: 0.9375rem;              /* was 0.95rem */
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s ease;          /* was opacity 0.2s, transform 0.1s */
  padding: 12px 20px;
  letter-spacing: 0.01em;             /* NEW */
}

.btn:active {
  transform: scale(0.98);            /* was 0.97 -- less aggressive */
}

.btn:disabled {
  opacity: 0.35;                     /* was 0.4 -- slightly more dimmed */
  cursor: not-allowed;
}
```

#### 5.5.2 Primary Button

```css
.btn-primary {
  background: var(--color-primary);    /* deep navy */
  color: var(--color-white);
  width: 100%;
  margin-top: 8px;
  padding: 14px;
  font-size: 0.9375rem;               /* was 1rem */
  border-radius: var(--radius-md);     /* 10px -- more rounded than default 6px */
  letter-spacing: 0.01em;
}

.btn-primary:hover:not(:disabled) {
  background: var(--color-primary-light); /* lighter navy -- NOT opacity change */
  box-shadow: var(--shadow-sm);           /* NEW: subtle lift */
}
```

**Key change:** Hover uses a color shift rather than opacity. This is more polished.

#### 5.5.3 Secondary Button (Log Out)

```css
.btn-secondary {
  background: transparent;
  color: var(--color-text-secondary);  /* was --color-muted */
  border: 1.5px solid var(--color-border-strong); /* was 1px solid --color-border */
  width: 100%;
  margin-top: 16px;                    /* was 12px */
  border-radius: var(--radius-md);     /* match primary */
  font-weight: 500;                    /* was 600 -- lighter to de-emphasize */
}

.btn-secondary:hover {
  background: var(--color-bg);
  border-color: var(--color-primary-muted); /* NEW: border darkens on hover */
  color: var(--color-text);                 /* NEW: text darkens on hover */
}
```

#### 5.5.4 Action Grid Buttons

```css
.action-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 10px;                           /* was 12px */
  margin-bottom: 20px;                 /* was 16px */
}

.btn-action {
  background: var(--color-white);
  color: var(--color-primary);
  border: 1.5px solid var(--color-border-strong); /* was 2px solid --color-primary */
  border-radius: var(--radius-md);                /* was --radius-sm */
  padding: 16px 12px;                             /* was 18px 12px */
  font-size: 0.8125rem;                           /* was 0.85rem */
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s ease;
}

.btn-action:hover {
  background: var(--color-primary);
  color: var(--color-white);
  border-color: var(--color-primary);
  box-shadow: var(--shadow-sm);        /* NEW: subtle lift */
}

.btn-action:active {
  transform: scale(0.98);             /* was 0.97 */
}
```

**Key change:** Action buttons now have a lighter border (`--color-border-strong` instead of `--color-primary`). This makes the grid feel calmer and less "boxy." The hover still fills navy for clear affordance.

#### 5.5.5 Footer Buttons (Danger/Warning Small)

```css
.btn-danger-small {
  background: transparent;
  color: var(--color-danger);
  border: 1.5px solid var(--color-danger);  /* was 1px */
  font-size: 0.75rem;                       /* was 0.8rem */
  font-weight: 500;
  padding: 8px 16px;
  border-radius: var(--radius-pill);         /* was --radius-sm -- pill shape */
  cursor: pointer;
  transition: all 0.2s ease;
  text-transform: uppercase;                 /* NEW */
  letter-spacing: 0.04em;                    /* NEW */
}

.btn-danger-small:hover {
  background: var(--color-danger-bg);        /* was full --color-failure fill */
  color: var(--color-danger);                /* keep text color -- no white fill */
  border-color: var(--color-danger);
}

.btn-warning-small {
  background: transparent;
  color: var(--color-warning);               /* was --color-accent (gold) */
  border: 1.5px solid var(--color-warning);  /* was 1px */
  font-size: 0.75rem;                        /* was 0.8rem */
  font-weight: 500;
  padding: 8px 16px;
  border-radius: var(--radius-pill);         /* pill shape */
  cursor: pointer;
  transition: all 0.2s ease;
  text-transform: uppercase;                 /* NEW */
  letter-spacing: 0.04em;                    /* NEW */
}

.btn-warning-small:hover {
  background: var(--color-warning-bg);       /* soft amber fill, not solid */
  color: var(--color-warning);
}

.btn-warning-small:disabled {
  opacity: 0.35;
  cursor: not-allowed;
}
```

**Key change:** Footer buttons become pill-shaped with uppercase text and soft-fill hovers instead of solid color hovers. This is much more restrained and professional. Destructive actions should not have a strong visual "invitation" to click.

---

### 5.6 Toggle Switches

**Current state:** Gray/gold toggle with `48x26px` track.

**New design:**

```css
.toggle-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin: 20px 0;                      /* was 16px 0 */
  padding: 12px 16px;                  /* NEW: add background container */
  background: var(--color-bg-warm);    /* NEW */
  border-radius: var(--radius-md);     /* NEW */
}

.toggle-label {
  font-size: 0.8125rem;               /* was 0.9rem */
  font-weight: 600;                    /* was 500 */
  color: var(--color-text);
  cursor: pointer;
}

.toggle-switch {
  position: relative;
  display: inline-block;
  width: 44px;                         /* was 48px -- slightly narrower */
  height: 24px;                        /* was 26px */
  cursor: pointer;
}

.toggle-switch input {
  opacity: 0;
  width: 0;
  height: 0;
}

.toggle-slider {
  position: absolute;
  inset: 0;
  background: var(--color-border-strong); /* was #ccc -- more intentional gray */
  border-radius: 24px;                   /* match height */
  transition: background 0.25s;
}

.toggle-slider::before {
  content: "";
  position: absolute;
  width: 18px;                         /* was 20px */
  height: 18px;                        /* was 20px */
  left: 3px;
  bottom: 3px;
  background: var(--color-white);
  border-radius: 50%;
  transition: transform 0.25s;
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.15); /* slightly lighter shadow */
}

.toggle-switch input:checked + .toggle-slider {
  background: var(--color-accent);     /* teal instead of gold */
}

.toggle-switch input:checked + .toggle-slider::before {
  transform: translateX(20px);         /* was 22px -- adjusted for new width */
}
```

**Key change:** The toggle row now has a subtle background container (`--color-bg-warm` with rounded corners). This groups the label and switch visually, a pattern common in banking/settings UIs. The toggle itself uses teal green for the "on" state.

---

### 5.7 Challenge Display Sections (Terminal Style)

This is the most significant visual change. These sections currently look like plain expandable text. They need to become dark "terminal" blocks that convey cryptographic operations.

**New design:**

```css
.challenge-display {
  margin-top: 24px;                    /* was 16px */
  background: var(--color-terminal-bg); /* NEW: dark terminal background */
  border-radius: var(--radius-md);      /* NEW */
  padding: 16px;                        /* NEW */
  border: 1px solid var(--color-terminal-border); /* NEW */
}

.challenge-section-header {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 8px;                  /* was 4px */
}

.challenge-section-label {
  font-size: 0.75rem;                  /* was 0.8rem */
  font-weight: 700;
  color: var(--color-terminal-label);  /* cyan/sky-blue on dark bg */
  text-transform: uppercase;            /* NEW */
  letter-spacing: 0.06em;              /* NEW */
  font-family: var(--font-mono);       /* NEW: monospace for terminal feel */
}

.challenge-display details {
  margin-bottom: 6px;                  /* was 8px */
}

.challenge-display summary {
  font-size: 0.75rem;                  /* was 0.85rem */
  font-weight: 500;                    /* was 600 */
  color: var(--color-terminal-summary); /* slate gray on dark */
  cursor: pointer;
  list-style: none;
  padding: 6px 0;                      /* was 4px 0 */
  font-family: var(--font-mono);       /* NEW */
  transition: color 0.2s;
}

.challenge-display summary:hover {
  color: var(--color-terminal-text);   /* NEW: brighten on hover */
}

.challenge-display summary::-webkit-details-marker { display: none; }

.challenge-display summary::before {
  content: "\25B6";
  display: inline-block;
  margin-right: 8px;                   /* was 6px */
  font-size: 0.55rem;                  /* was 0.65rem */
  transition: transform 0.2s;
  vertical-align: middle;
  color: var(--color-terminal-label);  /* NEW: cyan arrow */
}

.challenge-display details[open] > summary::before {
  transform: rotate(90deg);
}

.challenge-value {
  font-weight: 400;
  color: var(--color-terminal-value);  /* green on dark -- was --color-muted */
  font-family: var(--font-mono);
  font-size: 0.75rem;                  /* was 0.8rem */
}

.challenge-full {
  font-size: 0.6875rem;               /* was 0.75rem -- slightly smaller */
  font-family: var(--font-mono);
  color: var(--color-terminal-text);   /* light text on dark */
  background: rgba(0, 0, 0, 0.3);     /* darker inset within terminal block */
  border: 1px solid var(--color-terminal-border);
  border-radius: var(--radius-sm);
  padding: 10px 12px;
  margin-top: 6px;
  white-space: pre-wrap;
  word-break: break-all;
  max-height: 120px;
  overflow-y: auto;
}

/* Custom scrollbar for terminal sections (webkit) */
.challenge-full::-webkit-scrollbar {
  width: 6px;
}
.challenge-full::-webkit-scrollbar-track {
  background: transparent;
}
.challenge-full::-webkit-scrollbar-thumb {
  background: var(--color-terminal-border);
  border-radius: 3px;
}
```

**Key changes:**
- The entire `.challenge-display` block gets a dark (`#0f172a`) background with padding and rounded corners, creating a distinct "terminal" zone within the card.
- All text inside switches to light-on-dark colors: cyan labels, green values, slate-gray summary text.
- The expanded `<pre>` blocks use a slightly darker inset (`rgba(0,0,0,0.3)`) within the already-dark parent.
- Custom scrollbar styling keeps the terminal aesthetic.
- Auth icons (`.auth-icon`) inside the terminal sections should get a subtle filter to remain visible: add `filter: brightness(0) invert(1); opacity: 0.6;` when inside `.challenge-display`.

```css
.challenge-display .auth-icon {
  filter: brightness(0) invert(1);    /* make icons white */
  opacity: 0.6;
}
```

---

### 5.8 Status Pills

**Current state:** White pills with light border, centered flex-wrap.

**New design:**

```css
.status-pills {
  display: flex;
  flex-wrap: wrap;
  justify-content: center;
  gap: 8px;                            /* was 12px -- tighter */
  margin-top: 24px;                    /* was 20px */
  margin-bottom: 4px;                  /* was 12px */
}

.pill {
  font-size: 0.6875rem;               /* was 0.75rem */
  color: var(--color-text-secondary);
  background: var(--color-bg);         /* was --color-white */
  padding: 5px 12px;                   /* was 4px 12px */
  border-radius: var(--radius-pill);   /* was 20px -- use pill token */
  border: 1px solid var(--color-border);
  font-weight: 500;                    /* NEW */
  letter-spacing: 0.02em;             /* NEW */
}

.pill b {
  color: var(--color-text);
  font-weight: 700;                    /* was 600 */
}
```

**Key changes:**
- Pills get a slightly gray background (`--color-bg`) instead of pure white, making them feel like embedded badges rather than floating chips.
- Slightly smaller text, tighter gap.

---

### 5.9 Flash Status Messages

```css
.flash {
  min-height: 0;
  border-radius: var(--radius-md);     /* was --radius-sm */
  text-align: center;
  font-weight: 600;
  font-size: 0.8125rem;               /* was 0.9rem */
  padding: 0;
  margin-bottom: 0;
  overflow: hidden;
  transition: all 0.3s ease;
}

.flash.success {
  background: var(--color-success-bg); /* light green bg instead of solid */
  color: var(--color-success);         /* green text instead of white */
  border: 1px solid var(--color-success); /* NEW */
  padding: 12px;
  margin-bottom: 12px;
}

.flash.failure {
  background: var(--color-danger-bg);  /* light red bg instead of solid */
  color: var(--color-danger);          /* red text instead of white */
  border: 1px solid var(--color-danger); /* NEW */
  padding: 12px;
  margin-bottom: 12px;
}
```

**Key change:** Flash messages use soft-colored backgrounds with colored text and borders instead of solid saturated fills. This is standard in modern banking UIs -- less alarming, more informative.

---

### 5.10 Footer

```css
.footer {
  max-width: 480px;
  width: 100%;
  margin-top: 20px;                    /* was 24px */
  display: flex;
  justify-content: center;
  gap: 12px;
}
```

Minor change: slightly reduced top margin. The button changes in section 5.5.5 above carry the bulk of the footer redesign (pill shape, uppercase, soft hover fills).

---

### 5.11 Confirmation Popup

```css
.popup-overlay {
  position: fixed;
  inset: 0;
  background: rgba(15, 43, 70, 0.6);  /* was rgba(0,0,0,0.5) -- navy tint */
  display: none;
  align-items: center;
  justify-content: center;
  z-index: 1000;
  padding: 16px;
  backdrop-filter: blur(4px);          /* NEW: frosted glass effect */
  -webkit-backdrop-filter: blur(4px);  /* Safari */
}

.popup-card {
  background: var(--color-white);
  border-radius: var(--radius-lg);     /* was --radius (12px), now 14px */
  padding: 32px 28px;                  /* was 28px 24px */
  max-width: 400px;
  width: 100%;
  box-shadow: var(--shadow-lg);        /* was custom -- use token */
  border: 1px solid var(--color-border); /* NEW */
}

.popup-card #popup-message {
  font-size: 0.9375rem;               /* was 1rem */
  font-weight: 500;
  color: var(--color-text);            /* was --color-primary */
  margin-bottom: 24px;                 /* was 20px */
  line-height: 1.6;                    /* was 1.5 */
}

.popup-buttons {
  display: flex;
  gap: 12px;
}

.popup-buttons .btn {
  flex: 1;
  margin-top: 0;
  border-radius: var(--radius-md);     /* match main buttons */
}
```

**Key changes:**
- Navy-tinted overlay with `backdrop-filter: blur(4px)` for a frosted glass effect.
- Popup card gets the same border treatment as the main card.
- Message text uses the general text color instead of primary navy.

---

## 6. Responsive Breakpoints

Keep a single breakpoint at `max-width: 520px` (mobile). Optionally add a second at `min-width: 521px` for desktop-specific refinements.

### Mobile (max-width: 520px)

```css
@media (max-width: 520px) {
  body {
    padding: 20px 12px;               /* was 16px 12px */
  }

  .header {
    margin-bottom: 20px;              /* was 28px at desktop */
  }

  .header h1 {
    font-size: 1.25rem;               /* was 1.3rem */
  }

  .subtitle {
    font-size: 0.75rem;               /* slightly smaller */
  }

  .card {
    padding: 24px 20px;               /* unchanged from current */
    border-radius: var(--radius-md);   /* 10px instead of 14px */
  }

  .username-row {
    margin-bottom: 16px;              /* tighter on mobile */
  }

  .toggle-row {
    margin: 16px 0;
    padding: 10px 14px;               /* tighter container */
  }

  .action-grid {
    gap: 8px;
  }

  .btn-action {
    padding: 14px 8px;
    font-size: 0.75rem;               /* was 0.8rem */
  }

  .challenge-display {
    padding: 12px;                     /* was 16px */
    margin-top: 20px;
  }

  .status-pills {
    gap: 6px;                          /* was 8px at mobile */
  }

  .pill {
    font-size: 0.625rem;              /* was 0.7rem */
    padding: 4px 8px;
  }

  /* Force Passkeys+ pill onto its own row */
  .pill:nth-child(4) {
    flex-basis: 100%;
    text-align: center;
  }

  .footer {
    margin-top: 16px;
  }

  .popup-card {
    padding: 24px 20px;
    border-radius: var(--radius-md);
  }
}
```

### Desktop Enhancements (min-width: 521px)

No additional `@media` block needed -- the base styles ARE the desktop styles. The current single-breakpoint approach is correct for this simple layout.

---

## 7. HTML Changes

These are the **only** HTML modifications needed (minimal):

1. **Logo swap:** In `index.html` line 24, change:
   ```html
   <!-- FROM -->
   <img src="./swissbit-logo.svg" alt="Swissbit" class="logo logo-swissbit">
   <!-- TO -->
   <img src="./swissbit_logo.png" alt="Swissbit" class="logo logo-swissbit">
   ```

2. **No other HTML changes.** All visual changes are CSS-only.

---

## 8. Animation & Transitions

### Existing transitions to preserve
- `transition: border-color 0.2s` on input focus
- `transition: background 0.25s` on toggle slider
- `transition: transform 0.25s` on toggle knob
- `transition: all 0.3s ease` on flash messages

### New/modified transitions
- **Buttons:** Change from `transition: opacity 0.2s, transform 0.1s` to `transition: all 0.2s ease`. This enables smooth background-color and box-shadow transitions on hover.
- **Action buttons:** Already have `transition: background 0.2s, color 0.2s, transform 0.1s` -- change to `transition: all 0.2s ease` for consistency.
- **Challenge summary hover:** Add `transition: color 0.2s` for the terminal text color shift on hover.
- **Input focus:** Add `box-shadow` to the existing `border-color` transition for smooth focus ring appearance.
- **Popup overlay:** The `display: none/flex` toggle is handled by JS; no CSS transition needed (it's instantaneous by design).

### Transitions to avoid
- Do NOT add animation to screen transitions (`.screen.active` toggling). The instant show/hide is intentional for this type of auth flow.
- Do NOT add hover animations to status pills. They are informational, not interactive.

---

## 9. Implementation Checklist

The frontend-developer agent should process these in order:

- [ ] Add Google Fonts `@import` for Inter at top of `style.css`
- [ ] Replace all `:root` CSS custom properties with the new palette
- [ ] Add `--font-mono` custom property
- [ ] Update `body` font-family to include Inter
- [ ] Update header styles (`.header`, `.logo-row`, `.logo`, `.logo-swissbit`, `.logo-divider`, `h1`, `.subtitle`)
- [ ] Update card styles (`.card`)
- [ ] Update username row styles (`.username-row`, `label`, `#username`, readonly state)
- [ ] Update auth icon styles (`.auth-icon`)
- [ ] Update base button styles (`.btn`)
- [ ] Update primary button styles (`.btn-primary`)
- [ ] Update secondary button styles (`.btn-secondary`)
- [ ] Update action grid and action button styles (`.action-grid`, `.btn-action`)
- [ ] Update toggle switch styles (`.toggle-row`, `.toggle-label`, `.toggle-switch`, `.toggle-slider`)
- [ ] Redesign challenge display as terminal blocks (`.challenge-display`, all child selectors)
- [ ] Add `.challenge-display .auth-icon` filter rule
- [ ] Add custom scrollbar styles for `.challenge-full`
- [ ] Update status pill styles (`.status-pills`, `.pill`)
- [ ] Update flash message styles (`.flash`, `.flash.success`, `.flash.failure`)
- [ ] Update footer styles (`.footer`)
- [ ] Update danger/warning small button styles (`.btn-danger-small`, `.btn-warning-small`)
- [ ] Redesign confirmation popup (`.popup-overlay`, `.popup-card`, etc.)
- [ ] Update responsive breakpoint styles
- [ ] Swap logo in `index.html` from `swissbit-logo.svg` to `swissbit_logo.png`
- [ ] Visual QA: check all three screens (SETUP, LOGIN, ACTIONS)
- [ ] Verify mobile rendering at 375px and 520px widths
- [ ] Verify challenge sections render properly with dark background inside white card
