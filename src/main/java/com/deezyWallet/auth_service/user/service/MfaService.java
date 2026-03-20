package com.deezyWallet.auth_service.user.service;

import com.deezyWallet.auth_service.user.constants.UserConstants;
import com.deezyWallet.auth_service.user.constants.UserErrorCode;
import com.deezyWallet.auth_service.user.exception.MfaException;
import com.deezyWallet.auth_service.user.repository.UserRepository;
import dev.samstevens.totp.code.CodeGenerator;
import dev.samstevens.totp.code.CodeVerifier;
import dev.samstevens.totp.code.DefaultCodeGenerator;
import dev.samstevens.totp.code.DefaultCodeVerifier;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.secret.SecretGenerator;
import dev.samstevens.totp.time.SystemTimeProvider;
import dev.samstevens.totp.time.TimeProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

/**
 * TOTP (Time-based One-Time Password) MFA service.
 *
 * Library: dev.samstevens.totp (java-totp)
 * Algorithm: HMAC-SHA1 (RFC 6238 default, compatible with Google Authenticator,
 *            Authy, Microsoft Authenticator)
 * Period: 30 seconds
 * Digits: 6
 *
 * MFA SETUP FLOW:
 *   1. initSetup(userId) → generate TOTP secret, store encrypted in Redis
 *                          (not DB yet — not confirmed), return QR URI
 *   2. confirmSetup(userId, totpCode) → verify code against pending secret
 *                          → on success: encrypt secret, save to User.mfaSecret,
 *                            set mfaEnabled=true, delete Redis pending key
 *   3. (Optional) disable(userId) → clear mfaSecret, set mfaEnabled=false
 *
 * WHY store pending secret in Redis instead of DB?
 *   Until the user confirms by providing a valid TOTP code, we don't know
 *   if they successfully scanned the QR code. Storing an unconfirmed secret
 *   in DB and then overwriting on retry creates orphaned DB rows.
 *   Redis with a TTL (10 minutes) is the perfect holding area:
 *   auto-expires if user abandons setup, no DB cleanup needed.
 *
 * SECRET ENCRYPTION:
 *   The TOTP secret is AES-256 encrypted before storage (both Redis and DB).
 *   Encryption/decryption is delegated to EncryptionService (not shown —
 *   wraps javax.crypto.Cipher AES/GCM/NoPadding with a KMS-managed key).
 *   For simplicity in this implementation, the secret is stored as-is with
 *   a TODO marker for encryption integration.
 *
 * TOTP WINDOW TOLERANCE:
 *   UserConstants.TOTP_WINDOW = 1 → accepts codes from 1 window before/after
 *   current (i.e. ±30 seconds). Accommodates clock skew on user devices.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class MfaService {

	private final RedisTemplate<String, String> redisTemplate;
	private final UserRepository                userRepository;

	private final SecretGenerator secretGenerator = new DefaultSecretGenerator();
	private final TimeProvider    timeProvider    = new SystemTimeProvider();
	private final CodeGenerator   codeGenerator   = new DefaultCodeGenerator();
	private final CodeVerifier    codeVerifier    = new DefaultCodeVerifier(codeGenerator, timeProvider) {{
		setAllowedTimePeriodDiscrepancy(UserConstants.TOTP_WINDOW);
	}};

	// ── MFA Setup ─────────────────────────────────────────────────────────────

	/**
	 * Initiates MFA setup — generates a secret and returns the QR URI.
	 * Secret is held in Redis until confirmed.
	 *
	 * @return otpauth:// URI for QR code generation
	 */
	public String initSetup(String userId, String email) {
		String secret = secretGenerator.generate();

		// Store pending secret in Redis with setup TTL
		redisTemplate.opsForValue().set(
				pendingSecretKey(userId),
				secret,  // TODO: encrypt with EncryptionService before storing
				UserConstants.MFA_PENDING_TTL_SECONDS,
				TimeUnit.SECONDS
		);

		// Build the otpauth URI (Google Authenticator format)
		String otpauthUri = String.format(
				"otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30",
				UserConstants.TOTP_ISSUER,
				email,
				secret,
				UserConstants.TOTP_ISSUER
		);

		log.info("MFA setup initiated for userId={}", userId);
		return otpauthUri;
	}

	/**
	 * Confirms MFA setup by verifying the first TOTP code from the user's device.
	 * On success, persists the encrypted secret to User entity and activates MFA.
	 *
	 * @throws MfaException if setup was never initiated or TOTP code is invalid
	 */
	public String confirmSetup(String userId, String totpCode) {
		String pendingKey = pendingSecretKey(userId);
		String secret     = redisTemplate.opsForValue().get(pendingKey);

		if (secret == null) {
			throw new MfaException(UserErrorCode.MFA_TOTP_INVALID,
					"MFA setup session expired. Please restart setup.");
		}

		if (!codeVerifier.isValidCode(secret, totpCode)) {
			throw new MfaException(UserErrorCode.MFA_TOTP_INVALID,
					"Invalid TOTP code. Please check your authenticator app.");
		}

		// Consume the pending key — setup is complete
		redisTemplate.delete(pendingKey);

		log.info("MFA setup confirmed for userId={}", userId);
		return secret; // Caller (UserService) persists this encrypted to DB
	}

	/**
	 * Verifies a TOTP code during login (MFA gate).
	 * Does NOT consume any state — the code is time-based, not stored.
	 *
	 * @throws MfaException if code is invalid
	 */
	public void verifyTotpCode(String encryptedSecret, String totpCode) {
		String secret = encryptedSecret; // TODO: decrypt with EncryptionService

		if (!codeVerifier.isValidCode(secret, totpCode)) {
			throw new MfaException(UserErrorCode.MFA_TOTP_INVALID, "Invalid TOTP code.");
		}
	}

	/**
	 * Returns the Base32 manual entry key from the otpauth URI.
	 * Extracted from the secret for display to users who can't scan QR.
	 */
	public String generateManualEntryKey(String otpauthUri) {
		// Extract secret parameter from URI
		int start = otpauthUri.indexOf("secret=") + 7;
		int end   = otpauthUri.indexOf("&", start);
		return end > 0 ? otpauthUri.substring(start, end) : otpauthUri.substring(start);
	}

	private String pendingSecretKey(String userId) {
		return UserConstants.REDIS_MFA_PENDING_PREFIX + userId;
	}
}
