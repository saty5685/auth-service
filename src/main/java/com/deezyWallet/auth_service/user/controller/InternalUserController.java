package com.deezyWallet.auth_service.user.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.deezyWallet.auth_service.user.constants.UserConstants;
import com.deezyWallet.auth_service.user.dto.response.UserStatusResponse;
import com.deezyWallet.auth_service.user.service.UserService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * InternalUserController — machine-to-machine endpoints for other microservices.
 *
 * BASE PATH: /internal/v1/users
 * AUTH:      ROLE_INTERNAL_SERVICE (enforced at SecurityConfig route level)
 *
 * WHO CALLS THIS:
 *   - Wallet Service   → GET /{userId}/status before activating wallet
 *   - Transaction Service → GET /{userId}/status before allowing high-value txns
 *   - Ledger Service   → GET /{userId}/status for audit record enrichment
 *
 * NETWORK ISOLATION:
 *   In production, this controller's path prefix (/internal/**) should be
 *   blocked at the API Gateway level — external clients must never reach it.
 *   Internal services call it directly via Kubernetes service DNS (no gateway).
 *   The ROLE_INTERNAL_SERVICE JWT check is defence-in-depth.
 *
 * PRINCIPLE OF LEAST INFORMATION:
 *   Returns UserStatusResponse (userId, status, kycStatus, canTransact, loginLocked).
 *   No personal data (name, email, phone). Downstream services need only
 *   the ability to answer "can this user transact?" — nothing more.
 *
 * ENDPOINT INVENTORY:
 *   GET /{userId}/status  — user status by userId (primary key)
 *   GET /email/{email}/status — user status by email (for services that only have email)
 */
@RestController
@RequestMapping(UserConstants.API_INTERNAL_BASE)
@RequiredArgsConstructor
@Slf4j
public class InternalUserController {

	private final UserService userService;

	// ── GET /internal/v1/users/{userId}/status ────────────────────────────────

	/**
	 * Returns the operational status of a user.
	 *
	 * Primary lookup by userId (UUID). Used by services that received
	 * the userId from a Kafka event (e.g. Wallet Service knows userId from
	 * USER_REGISTERED event).
	 *
	 * Response fields:
	 *   userId      — echoed back for the caller to confirm they got the right user
	 *   status      — UserStatus enum (PENDING/ACTIVE/SUSPENDED/CLOSED)
	 *   kycStatus   — KycStatus enum (UNVERIFIED/PENDING/VERIFIED/REJECTED)
	 *   canTransact — computed boolean: status == ACTIVE
	 *   loginLocked — whether the account is in a temporary login lockout
	 *                 (informational for fraud detection — not blocking for transactions)
	 */
	@GetMapping("/{userId}/status")
	public ResponseEntity<UserStatusResponse> getUserStatus(@PathVariable String userId) {
		return ResponseEntity.ok(userService.getStatus(userId));
	}

	// ── GET /internal/v1/users/email/{email}/status ───────────────────────────

	/**
	 * Returns status by email address.
	 *
	 * Used by services that only have the email, not the userId.
	 * Example: Notification Service verifying a user before sending a message.
	 *
	 * Email is URL-encoded in the path — callers must encode @ as %40.
	 * Alternative design: accept as query param (?email=...) — simpler but
	 * email in query string gets logged by default in most HTTP access logs.
	 * Path encoding is more privacy-preserving.
	 */
	@GetMapping("/email/{email}/status")
	public ResponseEntity<UserStatusResponse> getUserStatusByEmail(@PathVariable String email) {
		// Delegate to UserService — needs a findByEmail variant
		// UserService.getStatusByEmail() is a thin wrapper around
		// userRepository.findByEmail(email).map(mapper::toStatusResponse)
		return ResponseEntity.ok(userService.getStatusByEmail(email));
	}
}
