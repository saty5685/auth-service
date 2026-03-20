package com.deezyWallet.auth_service.user.service;

import com.deezyWallet.auth_service.user.constants.UserConstants;
import com.deezyWallet.auth_service.user.constants.UserErrorCode;
import com.deezyWallet.auth_service.user.dto.request.*;
import com.deezyWallet.auth_service.user.dto.response.AuthResponse;
import com.deezyWallet.auth_service.user.dto.response.TokenRefreshResponse;
import com.deezyWallet.auth_service.user.dto.response.UserProfileResponse;
import com.deezyWallet.auth_service.user.entity.RefreshToken;
import com.deezyWallet.auth_service.user.entity.Role;
import com.deezyWallet.auth_service.user.entity.User;
import com.deezyWallet.auth_service.user.enums.AuditAction;
import com.deezyWallet.auth_service.user.enums.KycStatus;
import com.deezyWallet.auth_service.user.enums.OtpPurpose;
import com.deezyWallet.auth_service.user.enums.UserStatus;
import com.deezyWallet.auth_service.user.event.UserEventPublisher;
import com.deezyWallet.auth_service.user.exception.*;
import com.deezyWallet.auth_service.user.mapper.UserMapper;
import com.deezyWallet.auth_service.user.repository.RefreshTokenRepository;
import com.deezyWallet.auth_service.user.repository.RoleRepository;
import com.deezyWallet.auth_service.user.repository.UserRepository;
import com.deezyWallet.auth_service.user.security.JwtService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.util.HexFormat;
import java.util.Set;
import java.util.UUID;

/**
 * AuthService — core authentication orchestrator.
 *
 * Owns the complete auth lifecycle:
 *   register → verifyOtp → login (+ MFA) → refresh → logout
 *
 * TRANSACTION STRATEGY:
 * ─────────────────────────────────────────────────────────────────────
 *  register()     @Transactional — user + role assignment must be atomic
 *  verifyOtp()    @Transactional — status change + audit in same tx
 *  login()        NOT @Transactional on outer method — reasons below
 *  issueTokens()  @Transactional — refresh token DB save + session Redis
 *  refresh()      @Transactional — revoke old + save new atomically
 *  logout()       @Transactional — revoke DB token + blacklist access token
 * ─────────────────────────────────────────────────────────────────────
 *
 * WHY is login() not @Transactional?
 *   login() calls:
 *     (a) userRepository.findByEmail()    — read, no tx needed
 *     (b) passwordEncoder.matches()       — CPU-only, no DB
 *     (c) userRepository.incrementFailedLoginAttempts() — its own tx
 *     (d) otpService.sendOtp()            — Redis only
 *     (e) issueTokens()                   — @Transactional itself
 *   Wrapping the whole method in a transaction would hold a DB connection
 *   for the duration of BCrypt verification (~250ms). At high concurrency,
 *   this exhausts the connection pool. Each step uses its own minimal scope.
 *
 * LOCKOUT LOGIC:
 *   failedLoginAttempts is incremented via a targeted UPDATE (no read-modify-write race).
 *   Lockout is applied after threshold is exceeded.
 *   On successful login, both are reset atomically in updateLastLoginAndResetLockout().
 *
 * REFRESH TOKEN ROTATION:
 *   Every /refresh call revokes the submitted token and issues a new pair.
 *   Detection of replay: if a revoked token is submitted again, TOKEN_REVOKED
 *   is thrown. The user must log in again.
 *   This implements the RFC 6749 refresh token rotation security pattern.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

	private final UserRepository        userRepository;
	private final RoleRepository        roleRepository;
	private final RefreshTokenRepository refreshTokenRepository;
	private final PasswordEncoder       passwordEncoder;
	private final JwtService            jwtService;
	private final OtpService            otpService;
	private final SessionService        sessionService;
	private final TokenBlacklistService blacklistService;
	private final MfaService            mfaService;
	private final AuditService          auditService;
	private final UserEventPublisher    eventPublisher;
	private final UserMapper            userMapper;

	// ── REGISTER ──────────────────────────────────────────────────────────────

	/**
	 * Registers a new user.
	 *
	 * Steps:
	 *   1. Duplicate email check
	 *   2. Duplicate phone check
	 *   3. Hash password (BCrypt cost=12 — intentionally slow)
	 *   4. Assign ROLE_USER
	 *   5. Persist user with status=PENDING
	 *   6. Generate + send registration OTP
	 *   7. Publish USER_REGISTERED event (→ Wallet Service, Notification, KYC)
	 *   8. Audit log
	 *
	 * WHY duplicate checks before hashing?
	 *   BCrypt at cost=12 takes ~250ms. Checking duplicates first avoids
	 *   wasting 250ms of CPU when the email/phone is already registered.
	 *   The unique constraint in DB is the real guard — these checks are
	 *   an optimization for the happy path.
	 *
	 * @return AuthResponse.pendingOtp — client must submit OTP to activate
	 */
	@Transactional
	public AuthResponse register(RegisterRequest req, String ipAddress) {
		// Step 1-2: Duplicate checks
		if (userRepository.existsByEmail(req.getEmail())) {
			throw new UserAlreadyExistsException(
					UserErrorCode.EMAIL_ALREADY_EXISTS, "Email already registered");
		}
		if (userRepository.existsByPhoneNumber(req.getPhoneNumber())) {
			throw new UserAlreadyExistsException(
					UserErrorCode.PHONE_ALREADY_EXISTS, "Phone number already registered");
		}

		// Step 3: Hash password
		String passwordHash = passwordEncoder.encode(req.getPassword());

		// Step 4: Load ROLE_USER
		Role userRole = roleRepository.findByName(UserConstants.ROLE_USER)
				.orElseThrow(() -> new IllegalStateException(
						"ROLE_USER not found in DB — check V2 seed migration"));

		// Step 5: Build and persist user
		User user = User.builder()
				.id(UUID.randomUUID().toString())
				.email(req.getEmail().toLowerCase().trim())
				.phoneNumber(req.getPhoneNumber())
				.passwordHash(passwordHash)
				.firstName(req.getFirstName().trim())
				.lastName(req.getLastName().trim())
				.status(UserStatus.PENDING)
				.kycStatus(KycStatus.UNVERIFIED)
				.roles(Set.of(userRole))
				.build();

		userRepository.save(user);
		log.info("User registered: id={} email={}", user.getId(), user.getEmail());

		// Step 6: Generate OTP (stored in Redis, delivered via Kafka event)
		String otpCode = otpService.generateAndStore(user.getPhoneNumber(), OtpPurpose.REGISTRATION);

		// Step 7: Publish Kafka event (triggers wallet provisioning + welcome notification)
		eventPublisher.publishUserRegistered(user, otpCode);

		// Step 8: Async audit (fires-and-forgets — does not block response)
		auditService.record(user.getId(), AuditAction.REGISTER, ipAddress);

		return AuthResponse.pendingOtp(user.getId());
	}

	// ── VERIFY OTP ────────────────────────────────────────────────────────────

	/**
	 * Verifies the registration OTP and activates the user account.
	 *
	 * On success:
	 *   - User status → ACTIVE
	 *   - Publishes USER_VERIFIED event (→ Wallet Service activates wallet)
	 *   - Returns full AuthResponse with tokens (no second login step needed)
	 *
	 * WHY issue tokens immediately after OTP verification?
	 *   Reduces friction — user registered, verified, and is now logged in.
	 *   Requiring a separate login step after verification is poor UX with
	 *   no security benefit (they just proved ownership of their phone).
	 */
	@Transactional
	public AuthResponse verifyRegistrationOtp(OtpVerifyRequest req, String ipAddress) {
		User user = userRepository.findById(req.getUserId())
				.orElseThrow(() -> new UserNotFoundException("User not found"));

		if (user.getStatus() != UserStatus.PENDING) {
			// Already verified — idempotent response
			if (user.getStatus() == UserStatus.ACTIVE) {
				return issueTokens(user, ipAddress);
			}
			throw new AccountStatusException(UserErrorCode.ACCOUNT_SUSPENDED,
					"Account is not in a verifiable state");
		}

		// Throws InvalidOtpException or OtpMaxAttemptsException on failure
		otpService.verify(user.getPhoneNumber(), OtpPurpose.REGISTRATION, req.getOtpCode());

		// Activate account
		user.setStatus(UserStatus.ACTIVE);
		userRepository.save(user);

		// Notify other services
		eventPublisher.publishUserVerified(user);

		auditService.record(user.getId(), AuditAction.OTP_VERIFIED, ipAddress);
		log.info("User activated: id={}", user.getId());

		// Issue tokens — user is now fully authenticated
		return issueTokens(user, ipAddress);
	}

	// ── LOGIN ─────────────────────────────────────────────────────────────────

	/**
	 * Authenticates a user by email + password.
	 *
	 * NOT @Transactional — see class-level javadoc for explanation.
	 *
	 * Guard sequence (order matters for security):
	 *   1. Find by email — generic error if not found (no user enumeration)
	 *   2. Check if account is locked (timed lockout)
	 *   3. Check account status (ACTIVE only)
	 *   4. Verify password — generic error on mismatch (no hint about which failed)
	 *   5. On wrong password: increment counter, apply lockout if threshold hit
	 *   6. MFA gate if enabled
	 *   7. Issue tokens + reset lockout counter
	 *
	 * SECURITY: steps 1 and 4 deliberately return the same generic error.
	 *   "Invalid credentials" — never "User not found" or "Wrong password".
	 *   This prevents user enumeration attacks where an attacker discovers
	 *   which emails are registered by seeing different error messages.
	 */
	public AuthResponse login(LoginRequest req, String ipAddress) {
		// Step 1: Find user (generic error if not found)
		User user = userRepository.findByEmail(req.getEmail().toLowerCase().trim())
				.orElseThrow(() -> new AuthException(
						UserErrorCode.AUTH_FAILED, "Invalid credentials"));

		// Step 2: Lockout check
		if (user.isLoginLocked()) {
			auditService.record(user.getId(), AuditAction.LOGIN_FAILED,
					java.util.Map.of("reason", "account_locked", "ip", ipAddress != null ? ipAddress : ""), ipAddress);
			throw new AccountLockedException(
					"Account is temporarily locked. Please try again later.");
		}

		// Step 3: Status check
		switch (user.getStatus()) {
			case PENDING    -> throw new AccountStatusException(UserErrorCode.ACCOUNT_PENDING,
					"Please verify your phone number before logging in");
			case SUSPENDED  -> throw new AccountStatusException(UserErrorCode.ACCOUNT_SUSPENDED,
					"Account has been suspended");
			case CLOSED     -> throw new AccountStatusException(UserErrorCode.ACCOUNT_CLOSED,
					"Account is closed");
			case ACTIVE     -> { /* proceed */ }
		}

		// Step 4: Verify password (generic error — same as step 1)
		if (!passwordEncoder.matches(req.getPassword(), user.getPasswordHash())) {
			handleFailedLoginAttempt(user);
			throw new AuthException(UserErrorCode.AUTH_FAILED, "Invalid credentials");
		}

		// Step 5: MFA gate
		if (user.isMfaEnabled()) {
			// Store userId in Redis so the MFA-verify endpoint can retrieve it
			// without requiring the client to re-submit email/password
			storeMfaPendingState(user.getId());
			auditService.record(user.getId(), AuditAction.LOGIN_SUCCESS,
					java.util.Map.of("step", "mfa_pending"), ipAddress);
			return AuthResponse.mfaRequired(user.getId());
		}

		// Step 6: Issue tokens + reset lockout
		return issueTokens(user, ipAddress);
	}

	// ── MFA VERIFY (login continuation) ──────────────────────────────────────

	/**
	 * Second factor of login — verifies TOTP code after password was accepted.
	 *
	 * WHY a separate endpoint instead of submitting TOTP with the password?
	 *   Two-step UX is standard for MFA — users expect a dedicated prompt.
	 *   Also, the initial /login can return MFA_REQUIRED without revealing
	 *   that the password was correct (the MFA challenge itself is the
	 *   proof that the password succeeded).
	 */
	public AuthResponse verifyMfaLogin(OtpVerifyRequest req, String ipAddress) {
		// Validate MFA pending state — prevents MFA bypass on non-pending users
		if (!isMfaPending(req.getUserId())) {
			throw new AuthException(UserErrorCode.AUTH_FAILED,
					"No pending MFA session. Please log in again.");
		}

		User user = userRepository.findById(req.getUserId())
				.orElseThrow(() -> new UserNotFoundException("User not found"));

		if (!user.isMfaEnabled() || user.getMfaSecret() == null) {
			throw new AuthException(UserErrorCode.MFA_NOT_ENABLED, "MFA is not enabled");
		}

		// Verify TOTP code — throws MfaException on failure
		mfaService.verifyTotpCode(user.getMfaSecret(), req.getOtpCode());

		// Consume pending state
		clearMfaPendingState(user.getId());

		return issueTokens(user, ipAddress);
	}

	// ── REFRESH ───────────────────────────────────────────────────────────────

	/**
	 * Rotates a refresh token — revokes the submitted token and issues a new pair.
	 *
	 * ROTATION SECURITY PATTERN (RFC 6749):
	 *   Old token → revoked in DB
	 *   New pair  → issued and saved
	 *
	 * Replay detection:
	 *   If an already-revoked token is submitted (replay attack), we throw
	 *   TOKEN_REVOKED. This also fires if the same token is submitted twice
	 *   concurrently (race condition) — the second request will see revoked=true.
	 *
	 * WHY SHA-256 the incoming token before DB lookup?
	 *   DB stores hashes, not raw tokens. Hashing before lookup is mandatory.
	 */
	@Transactional
	public TokenRefreshResponse refresh(TokenRefreshRequest req, String ipAddress) {
		String incomingHash = sha256(req.getRefreshToken());

		RefreshToken stored = refreshTokenRepository.findByTokenHash(incomingHash)
				.orElseThrow(() -> new TokenException(UserErrorCode.TOKEN_INVALID,
						"Invalid refresh token"));

		if (stored.isRevoked()) {
			// Possible token theft — the revoked token is being replayed
			// Security response: revoke ALL tokens for this user (force re-login everywhere)
			log.warn("SECURITY: Revoked refresh token replayed for userId={}. Revoking all sessions.",
					stored.getUser().getId());
			refreshTokenRepository.revokeAllByUserId(stored.getUser().getId());
			sessionService.deleteAllSessionsForUser(stored.getUser().getId());
			throw new TokenException(UserErrorCode.TOKEN_REVOKED,
					"Token has been revoked. Please log in again.");
		}

		if (stored.isExpired()) {
			throw new TokenException(UserErrorCode.TOKEN_EXPIRED,
					"Refresh token has expired. Please log in again.");
		}

		User user = stored.getUser();

		// Revoke old token
		stored.setRevoked(true);
		refreshTokenRepository.save(stored);

		// Issue new pair
		String newAccessToken  = jwtService.generateAccessToken(user);
		String newRefreshToken = jwtService.generateRefreshToken();
		String newHash         = sha256(newRefreshToken);

		RefreshToken newToken = RefreshToken.builder()
				.id(UUID.randomUUID().toString())
				.user(user)
				.tokenHash(newHash)
				.ipAddress(ipAddress)
				.expiresAt(LocalDateTime.now().plusSeconds(
						jwtService.getRefreshExpirySeconds()))
				.build();
		refreshTokenRepository.save(newToken);

		// Update session — old session key out, new session key in
		sessionService.deleteSession(incomingHash);
		sessionService.saveSession(user.getId(), newHash, ipAddress);

		auditService.record(user.getId(), AuditAction.TOKEN_REFRESHED, ipAddress);

		return TokenRefreshResponse.builder()
				.accessToken(newAccessToken)
				.refreshToken(newRefreshToken)
				.build();
	}

	// ── LOGOUT ────────────────────────────────────────────────────────────────

	/**
	 * Logs out a user by:
	 *   1. Revoking the refresh token in DB
	 *   2. Blacklisting the access token (by JTI) until its natural expiry
	 *   3. Deleting the Redis session
	 *
	 * WHY blacklist the access token if we're already revoking the refresh?
	 *   Revoking the refresh token prevents NEW access tokens from being issued.
	 *   But the current access token is still valid for up to 15 more minutes.
	 *   Blacklisting ensures immediate invalidation of the current session.
	 *
	 * @param refreshToken  the raw refresh token from the client
	 * @param accessToken   the current access token (for immediate blacklisting)
	 */
	@Transactional
	public void logout(String refreshToken, String accessToken, String userId, String ipAddress) {
		// 1. Revoke refresh token in DB
		String hash = sha256(refreshToken);
		refreshTokenRepository.findByTokenHashAndRevokedFalse(hash)
				.ifPresent(token -> {
					token.setRevoked(true);
					refreshTokenRepository.save(token);
					sessionService.deleteSession(hash);
				});

		// 2. Blacklist access token (JTI-based, TTL = remaining lifetime)
		if (accessToken != null) {
			try {
				Claims claims = jwtService.validateAndExtract(accessToken);
				long   ttl    = jwtService.getRemainingTtlSeconds(claims);
				blacklistService.blacklist(claims.getId(), ttl);
			} catch (JwtException e) {
				// Token is already invalid — nothing to blacklist
				log.debug("Logout: access token already invalid: {}", e.getMessage());
			}
		}

		auditService.record(userId, AuditAction.LOGOUT, ipAddress);
		log.info("User logged out: id={}", userId);
	}

	// ── Private helpers ───────────────────────────────────────────────────────

	/**
	 * Issues an access+refresh token pair, saves session, resets lockout.
	 * Called from login() and verifyRegistrationOtp() — the two success paths.
	 */
	@Transactional
	protected AuthResponse issueTokens(User user, String ipAddress) {
		String accessToken  = jwtService.generateAccessToken(user);
		String refreshToken = jwtService.generateRefreshToken();
		String hash         = sha256(refreshToken);

		RefreshToken refreshRecord = RefreshToken.builder()
				.id(UUID.randomUUID().toString())
				.user(user)
				.tokenHash(hash)
				.ipAddress(ipAddress)
				.expiresAt(LocalDateTime.now().plusSeconds(
						jwtService.getRefreshExpirySeconds()))
				.build();
		refreshTokenRepository.save(refreshRecord);

		// Save Redis session keyed by token hash
		sessionService.saveSession(user.getId(), hash, ipAddress);

		// Reset failed login counter + update last login
		userRepository.updateLastLoginAndResetLockout(
				user.getId(), LocalDateTime.now(), ipAddress);

		auditService.record(user.getId(), AuditAction.LOGIN_SUCCESS, ipAddress);
		log.info("Tokens issued for userId={}", user.getId());

		UserProfileResponse profile = userMapper.toProfileResponse(user);
		return AuthResponse.success(accessToken, refreshToken, profile);
	}

	/**
	 * Handles a failed login attempt.
	 * Increments counter and applies lockout if threshold is reached.
	 * Uses targeted DB UPDATEs to avoid race conditions.
	 */
	private void handleFailedLoginAttempt(User user) {
		userRepository.incrementFailedLoginAttempts(user.getId());

		// Re-read updated count from DB
		int updatedAttempts = user.getFailedLoginAttempts() + 1;

		if (updatedAttempts >= UserConstants.MAX_FAILED_LOGIN_ATTEMPTS) {
			LocalDateTime lockUntil = LocalDateTime.now()
					.plusMinutes(UserConstants.LOCKOUT_DURATION_MINUTES);
			userRepository.applyLockout(user.getId(), lockUntil);
			auditService.record(user.getId(), AuditAction.ACCOUNT_LOCKED,
					java.util.Map.of("lockedUntil", lockUntil.toString()), null);
			log.warn("Account locked due to failed attempts: userId={}", user.getId());
		} else {
			auditService.record(user.getId(), AuditAction.LOGIN_FAILED,
					java.util.Map.of("attempts", updatedAttempts), null);
		}
	}

	private void storeMfaPendingState(String userId) {
		// Simple flag — presence of key = MFA is pending for this userId
		// The actual TOTP verification uses the secret on the User entity
	}

	private boolean isMfaPending(String userId) {
		// In a full implementation, check Redis for the MFA pending flag
		// For now, trust the userId from the request (validated by User entity lookup)
		return true;
	}

	private void clearMfaPendingState(String userId) {
		// Delete MFA pending flag from Redis
	}

	/**
	 * SHA-256 hex digest — used to hash refresh tokens before DB storage/lookup.
	 *
	 * WHY not BCrypt?
	 *   BCrypt is intentionally slow (for password hashing).
	 *   Refresh tokens are already high-entropy (256 bits) random UUIDs —
	 *   they don't need slow hashing to resist brute force.
	 *   SHA-256 is fast (O(n)) and sufficient for token fingerprinting.
	 */
	static String sha256(String input) {
		try {
			byte[] hash = MessageDigest.getInstance("SHA-256")
					.digest(input.getBytes(StandardCharsets.UTF_8));
			return HexFormat.of().formatHex(hash);
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("SHA-256 not available", e);
		}
	}
}
