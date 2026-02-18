# Security notes

This document describes what the app **actually implements** today. It avoids security marketing terms and focuses on concrete design/implementation details.

## Data protection

- **Per-entry encryption**: each entry’s password is encrypted individually (AES-256-CBC).
- **Key derivation**: encryption keys are derived from the master password using PBKDF2 (100,000 iterations).
- **Per-entry salt + IV**: every entry has its own salt/IV to avoid ciphertext reuse.
- **Local storage**: data is stored locally in SQLite (ciphertext + metadata), no cloud sync by default.

## Master password handling

- Minimum length and complexity checks are enforced in the UI and backend.
- Authentication is performed via a stored hash (not by storing the master password).

## App hardening (Electron)

- Context isolation enabled; renderer uses a preload bridge (IPC).
- Node integration disabled in the renderer.
- Sandbox enabled for the renderer process.
- Content Security Policy (CSP) restricts resource loading (scripts, styles, connections).
- Clipboard auto-clear (30 s) in both vault copy and password generator.

Notes:
- UI hardening measures (e.g., blocking certain shortcuts/menus) are not a security boundary and should not be relied on against a motivated attacker with OS access.

## Session safety

- Auto-lock on inactivity (vault session ends and UI locks).
- Clipboard auto-clear after a timeout (best-effort).

## Recovery features

- Recovery via email-SMS flow (implementation is local-first; any “send code” behavior must be backed by a real provider in production).

## Limitations / threat model

- If the host OS is compromised (malware, keylogger, admin attacker), no password manager can fully guarantee safety.
- This project is intended as an offline-first desktop app demonstrating encryption, key-derivation, IPC isolation, and secure-ish UX patterns.
