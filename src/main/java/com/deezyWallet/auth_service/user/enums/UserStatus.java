package com.deezyWallet.auth_service.user.enums;

/**
 * Lifecycle states of a user account.
 *
 * State machine:
 *
 *   [NEW] ──register──→ PENDING ──verifyOtp──→ ACTIVE ──suspend──→ SUSPENDED
 *                                                  ↑                    │
 *                                                  └──────reinstate──────┘
 *                                     ACTIVE ──close──→ CLOSED (terminal)
 *
 * PENDING  — registered but phone OTP not yet verified; cannot log in
 * ACTIVE   — fully verified; all operations permitted
 * SUSPENDED — admin-locked; read-only, no transactions, no new logins
 * CLOSED   — voluntary account closure or compliance action; terminal state
 *
 * WHY these four and not more?
 *   Some systems add LOCKED (failed attempts) separately.
 *   We encode login lockout as fields on User (failedLoginAttempts + lockedUntil)
 *   rather than a status — that keeps the status enum as account lifecycle only,
 *   and login lockout can expire automatically without a status transition.
 */
public enum UserStatus {
	PENDING,
	ACTIVE,
	SUSPENDED,
	CLOSED;

	public boolean canLogin() {
		return this == ACTIVE;
	}

	public boolean canTransact() {
		return this == ACTIVE;
	}

	public boolean isTerminal() {
		return this == CLOSED;
	}
}
