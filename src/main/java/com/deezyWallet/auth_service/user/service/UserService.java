package com.deezyWallet.auth_service.user.service;

import com.deezyWallet.auth_service.user.constants.UserConstants;
import com.deezyWallet.auth_service.user.constants.UserErrorCode;
import com.deezyWallet.auth_service.user.dto.request.ChangePasswordRequest;
import com.deezyWallet.auth_service.user.dto.request.MfaConfirmRequest;
import com.deezyWallet.auth_service.user.dto.request.UpdateProfileRequest;
import com.deezyWallet.auth_service.user.dto.response.MfaSetupResponse;
import com.deezyWallet.auth_service.user.dto.response.UserProfileResponse;
import com.deezyWallet.auth_service.user.dto.response.UserStatusResponse;
import com.deezyWallet.auth_service.user.entity.User;
import com.deezyWallet.auth_service.user.enums.AuditAction;
import com.deezyWallet.auth_service.user.enums.UserStatus;
import com.deezyWallet.auth_service.user.event.UserEventPublisher;
import com.deezyWallet.auth_service.user.exception.*;
import com.deezyWallet.auth_service.user.mapper.UserMapper;
import com.deezyWallet.auth_service.user.repository.RefreshTokenRepository;
import com.deezyWallet.auth_service.user.repository.UserRepository;
import com.deezyWallet.auth_service.user.security.JwtService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * UserService — user profile and account lifecycle management.
 *
 * Responsibilities:
 *   - Profile reads and updates (self-service)
 *   - Password change (requires current password verification)
 *   - MFA enable/disable lifecycle
 *   - Account suspension / reinstatement (admin)
 *   - Status query (internal service endpoint)
 *   - Paginated user listing (admin)
 *
 * SEPARATION FROM AuthService:
 *   AuthService owns the authentication flow (tokens, sessions, OTP).
 *   UserService owns the user entity lifecycle (profile, status, credentials).
 *   This split keeps both classes focused and avoids a God class.
 *   The only shared dependency is UserRepository.
 *
 * TRANSACTION STRATEGY:
 *   All mutating methods are @Transactional.
 *   Read methods are @Transactional(readOnly = true) — signals the DB that
 *   no writes will occur, allowing read replicas and avoiding MVCC overhead.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class UserService {

	private final UserRepository         userRepository;
	private final RefreshTokenRepository refreshTokenRepository;
	private final PasswordEncoder        passwordEncoder;
	private final JwtService             jwtService;
	private final MfaService             mfaService;
	private final SessionService         sessionService;
	private final AuditService           auditService;
	private final UserEventPublisher     eventPublisher;
	private final UserMapper             userMapper;

	// ── Profile reads ─────────────────────────────────────────────────────────

	@Transactional(readOnly = true)
	public UserProfileResponse getProfile(String userId) {
		User user = findActiveUserById(userId);
		return userMapper.toProfileResponse(user);
	}

	/**
	 * Internal endpoint — returns minimal status for other microservices.
	 * No personal data — only what downstream services need for auth decisions.
	 */
	@Transactional(readOnly = true)
	public UserStatusResponse getStatus(String userId) {
		User user = userRepository.findById(userId)
				.orElseThrow(() -> new UserNotFoundException("User not found: " + userId));
		return userMapper.toStatusResponse(user);
	}

	// ── Profile update ────────────────────────────────────────────────────────

	/**
	 * Updates the user's name fields.
	 * Email and phone changes go through a separate verified flow (not here).
	 */
	@Transactional
	public UserProfileResponse updateProfile(String userId, UpdateProfileRequest req,
			String ipAddress) {
		User user = findActiveUserById(userId);

		user.setFirstName(req.getFirstName().trim());
		user.setLastName(req.getLastName().trim());
		userRepository.save(user);

		auditService.record(userId, AuditAction.PROFILE_UPDATED, ipAddress);
		log.info("Profile updated for userId={}", userId);

		return userMapper.toProfileResponse(user);
	}

	// ── Password change ───────────────────────────────────────────────────────

	/**
	 * Changes the user's password after verifying the current one.
	 *
	 * Post-change actions (all security-critical):
	 *   1. Revoke ALL refresh tokens → force re-login on all devices
	 *   2. Delete all Redis sessions
	 *   3. Publish PASSWORD_CHANGED event → Notification Service sends alert
	 *   4. Audit log
	 *
	 * WHY revoke all tokens on password change?
	 *   If an attacker gained access with the old password and has an active
	 *   refresh token, a password change without token revocation leaves their
	 *   session active. Token revocation invalidates any sessions the attacker
	 *   may hold.
	 *
	 * WHY NOT blacklist the current access token here?
	 *   The controller does this using the @AuthenticationPrincipal's JTI
	 *   after the service call returns. Separation of concerns: service changes
	 *   DB state, controller handles the current request's token.
	 */
	@Transactional
	public void changePassword(String userId, ChangePasswordRequest req, String ipAddress) {
		User user = findActiveUserById(userId);

		// Verify current password
		if (!passwordEncoder.matches(req.getCurrentPassword(), user.getPasswordHash())) {
			throw new AuthException(UserErrorCode.INVALID_CURRENT_PASSWORD,
					"Current password is incorrect");
		}

		// Apply new password
		user.setPasswordHash(passwordEncoder.encode(req.getNewPassword()));
		userRepository.save(user);

		// Revoke all sessions (security: attacker's session also revoked)
		refreshTokenRepository.revokeAllByUserId(userId);
		sessionService.deleteAllSessionsForUser(userId);

		// Notify user of password change
		eventPublisher.publishPasswordChanged(user);

		auditService.record(userId, AuditAction.PASSWORD_CHANGED, ipAddress);
		log.info("Password changed for userId={}", userId);
	}

	// ── MFA lifecycle ─────────────────────────────────────────────────────────

	/**
	 * Initiates MFA setup — generates TOTP secret, returns QR URI.
	 * MFA is not activated until confirmMfaSetup() is called successfully.
	 *
	 * @throws MfaException if MFA is already enabled
	 */
	@Transactional(readOnly = true)
	public MfaSetupResponse initMfaSetup(String userId) {
		User user = findActiveUserById(userId);

		if (user.isMfaEnabled()) {
			throw new MfaException(UserErrorCode.MFA_ALREADY_ENABLED,
					"MFA is already enabled on this account");
		}

		String otpauthUri     = mfaService.initSetup(userId, user.getEmail());
		String manualEntryKey = mfaService.generateManualEntryKey(otpauthUri);

		return MfaSetupResponse.builder()
				.otpauthUrl(otpauthUri)
				.manualEntryKey(manualEntryKey)
				.build();
	}

	/**
	 * Confirms MFA setup by verifying the first TOTP code.
	 * Persists the encrypted TOTP secret and sets mfaEnabled=true.
	 */
	@Transactional
	public void confirmMfaSetup(String userId, MfaConfirmRequest req, String ipAddress) {
		User user = findActiveUserById(userId);

		if (user.isMfaEnabled()) {
			throw new MfaException(UserErrorCode.MFA_ALREADY_ENABLED,
					"MFA is already enabled");
		}

		// Verifies TOTP code against pending secret in Redis
		// Returns the secret (for us to persist)
		String secret = mfaService.confirmSetup(userId, req.getTotpCode());

		// Persist the confirmed secret and activate MFA
		// TODO: encrypt secret with EncryptionService before storing
		user.setMfaSecret(secret);
		user.setMfaEnabled(true);
		userRepository.save(user);

		auditService.record(userId, AuditAction.MFA_ENABLED, ipAddress);
		log.info("MFA enabled for userId={}", userId);
	}

	/**
	 * Disables MFA — clears secret and flag.
	 * Requires a valid TOTP code as confirmation (can't be disabled accidentally).
	 */
	@Transactional
	public void disableMfa(String userId, MfaConfirmRequest req, String ipAddress) {
		User user = findActiveUserById(userId);

		if (!user.isMfaEnabled()) {
			throw new MfaException(UserErrorCode.MFA_NOT_ENABLED, "MFA is not enabled");
		}

		// Require a valid code to confirm the user intends to disable MFA
		mfaService.verifyTotpCode(user.getMfaSecret(), req.getTotpCode());

		user.setMfaEnabled(false);
		user.setMfaSecret(null);
		userRepository.save(user);

		auditService.record(userId, AuditAction.MFA_DISABLED, ipAddress);
		log.info("MFA disabled for userId={}", userId);
	}

	// ── Admin operations ──────────────────────────────────────────────────────

	/**
	 * Suspends a user account.
	 *
	 * Effects:
	 *   - Status → SUSPENDED
	 *   - All refresh tokens revoked (all devices logged out)
	 *   - All Redis sessions deleted
	 *   - USER_SUSPENDED event published (→ Wallet Service freezes wallet)
	 *
	 * WHY revoke tokens on suspend?
	 *   A suspended user must not continue using the service.
	 *   Existing access tokens are still valid for up to 15 minutes —
	 *   the JwtAuthFilter should add a status check on protected routes
	 *   for high-security endpoints. Revoking refresh tokens prevents renewal.
	 *
	 * @param targetUserId  the user to suspend
	 * @param adminId       the admin performing the action (for audit)
	 * @param reason        reason for suspension (stored in audit log)
	 */
	@Transactional
	public void suspendUser(String targetUserId, String adminId,
			String reason, String ipAddress) {
		User user = userRepository.findById(targetUserId)
				.orElseThrow(() -> new UserNotFoundException("User not found: " + targetUserId));

		if (user.getStatus() == UserStatus.SUSPENDED) {
			return; // Idempotent — already suspended
		}

		if (user.getStatus() == UserStatus.CLOSED) {
			throw new AccountStatusException(UserErrorCode.ACCOUNT_CLOSED,
					"Cannot suspend a closed account");
		}

		user.setStatus(UserStatus.SUSPENDED);
		userRepository.save(user);

		// Terminate all active sessions
		refreshTokenRepository.revokeAllByUserId(targetUserId);
		sessionService.deleteAllSessionsForUser(targetUserId);

		// Notify downstream services
		eventPublisher.publishUserSuspended(user);

		auditService.record(targetUserId, AuditAction.ACCOUNT_SUSPENDED,
				java.util.Map.of("adminId", adminId, "reason", reason != null ? reason : ""),
				ipAddress);
		log.warn("User suspended: targetId={} by adminId={} reason={}", targetUserId, adminId, reason);
	}

	/**
	 * Reinstates a suspended user account.
	 *
	 * @param targetUserId  the user to reinstate
	 * @param adminId       the admin performing the action
	 */
	@Transactional
	public void reinstateUser(String targetUserId, String adminId, String ipAddress) {
		User user = userRepository.findById(targetUserId)
				.orElseThrow(() -> new UserNotFoundException("User not found: " + targetUserId));

		if (user.getStatus() != UserStatus.SUSPENDED) {
			throw new AccountStatusException(UserErrorCode.ACCOUNT_SUSPENDED,
					"User is not suspended — cannot reinstate");
		}

		user.setStatus(UserStatus.ACTIVE);
		userRepository.save(user);

		eventPublisher.publishUserReinstated(user);

		auditService.record(targetUserId, AuditAction.ACCOUNT_REINSTATED,
				java.util.Map.of("adminId", adminId), ipAddress);
		log.info("User reinstated: targetId={} by adminId={}", targetUserId, adminId);
	}

	/**
	 * Returns a paginated list of users for admin management UI.
	 *
	 * Filtered by status when provided. Always paginated — never SELECT *.
	 */
	@Transactional(readOnly = true)
	public Page<UserProfileResponse> listUsers(UserStatus statusFilter, Pageable pageable) {
		Page<User> users = (statusFilter != null)
				? userRepository.findAllByStatus(statusFilter, pageable)
				: userRepository.findAll(pageable);

		return users.map(userMapper::toProfileResponse);
	}

	/**
	 * Admin: get full user profile by ID (includes status, KYC, etc.)
	 */
	@Transactional(readOnly = true)
	public UserProfileResponse getUserById(String userId) {
		User user = userRepository.findById(userId)
				.orElseThrow(() -> new UserNotFoundException("User not found: " + userId));
		return userMapper.toProfileResponse(user);
	}

	// ── Private helpers ───────────────────────────────────────────────────────

	/**
	 * Loads a user by ID and asserts they are ACTIVE.
	 * Used by all self-service operations that require an active account.
	 *
	 * WHY not just findById()?
	 *   A SUSPENDED user should not be able to update their profile, change
	 *   password, or modify MFA. Centralizing this check prevents
	 *   accidentally forgetting it in any individual method.
	 */
	private User findActiveUserById(String userId) {
		User user = userRepository.findById(userId)
				.orElseThrow(() -> new UserNotFoundException("User not found: " + userId));

		if (user.getStatus() != UserStatus.ACTIVE) {
			throw new AccountStatusException(UserErrorCode.ACCOUNT_SUSPENDED,
					"Operation not permitted for account status: " + user.getStatus());
		}

		return user;
	}
}
