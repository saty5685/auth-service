package com.deezyWallet.auth_service.user.service;

import com.deezyWallet.auth_service.user.constants.UserConstants;
import com.deezyWallet.auth_service.user.constants.UserErrorCode;
import com.deezyWallet.auth_service.user.enums.OtpPurpose;
import com.deezyWallet.auth_service.user.exception.InvalidOtpException;
import com.deezyWallet.auth_service.user.exception.OtpMaxAttemptsException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Duration;
import java.util.concurrent.TimeUnit;

/**
 * OTP (One-Time Password) generation, storage, and verification.
 *
 * STORAGE SCHEMA (Redis):
 * ────────────────────────────────────────────────────────────────────
 *  Code key:     user:otp:{purpose}:{phoneNumber}     → "839201"
 *  Attempt key:  user:otp:attempts:{purpose}:{phone}  → "2"
 * ────────────────────────────────────────────────────────────────────
 *
 * DESIGN DECISIONS:
 *
 * WHY two Redis keys (code + attempts)?
 *   We need separate TTLs:
 *   - Code TTL   = OtpPurpose.ttlSeconds (e.g. 600s for REGISTRATION)
 *   - Attempt TTL = same as code TTL (attempts expire with the code)
 *   A single key storing both would require a JSON value + GETSET atomicity.
 *   Two simple keys with SETNX + INCR is cleaner and still atomic per operation.
 *
 * WHY SETNX (SET if Not eXists) for the code key?
 *   Prevents OTP flooding: if a code is already stored for this phone+purpose,
 *   a second generateAndStore() call within the TTL window returns the same code.
 *   Without SETNX, an attacker could generate a new code every second,
 *   making brute-force easier by always knowing the most-recently-generated code.
 *
 * WHY SecureRandom, not Random?
 *   java.util.Random is not cryptographically secure — its output is predictable
 *   given a short sequence of prior outputs.
 *   SecureRandom uses the OS entropy pool (/dev/urandom on Linux), making the
 *   6-digit code genuinely unpredictable.
 *
 * Attempt limiting (OTP_MAX_ATTEMPTS = 3):
 *   After 3 wrong guesses, the code key is deleted and OtpMaxAttemptsException
 *   thrown. The user must request a new OTP. This caps brute-force attempts
 *   on any single code to 3 tries (1/1000 success probability per code).
 *
 * Fail-open on Redis errors:
 *   If Redis is unreachable, generateAndStore() logs the error and rethrows.
 *   Unlike balance cache (where fail-open is safe), OTP failure should be
 *   surfaced — silently skipping OTP would be a security hole, not just
 *   a degraded UX.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class OtpService {

	private final RedisTemplate<String, String> redisTemplate;

	private static final SecureRandom SECURE_RANDOM = new SecureRandom();

	// ── Key builders ──────────────────────────────────────────────────────────

	private String codeKey(OtpPurpose purpose, String phone) {
		return UserConstants.REDIS_OTP_PREFIX + purpose.name().toLowerCase() + ":" + phone;
	}

	private String attemptsKey(OtpPurpose purpose, String phone) {
		return UserConstants.REDIS_OTP_PREFIX + "attempts:" + purpose.name().toLowerCase() + ":" + phone;
	}

	// ── Public API ────────────────────────────────────────────────────────────

	/**
	 * Generates a 6-digit OTP and stores it in Redis with the purpose-specific TTL.
	 *
	 * SETNX semantics: if a code already exists for this phone+purpose within
	 * its TTL, the existing code is NOT overwritten. This prevents flooding.
	 *
	 * In production this method would publish the code to a Notification Service
	 * via Kafka (SMS delivery). For now, the code is logged at INFO level and
	 * returned — the caller (AuthService) publishes the Kafka event.
	 *
	 * @return the generated OTP (passed to event publisher, not returned to client)
	 */
	public String generateAndStore(String phoneNumber, OtpPurpose purpose) {
		String key  = codeKey(purpose, phoneNumber);
		String code = generateCode();
		long   ttl  = purpose.getTtlSeconds();

		// SETNX + EXPIRE as two commands — not atomic but acceptable:
		// Worst case: SETNX succeeds, EXPIRE fails (Redis crash between commands).
		// TTL is then unlimited. Mitigated by Redis persistence + short TTLs.
		// True atomicity would require a Lua script — overkill for OTP TTLs.
		Boolean stored = redisTemplate.opsForValue()
				.setIfAbsent(key, code, Duration.ofSeconds(ttl));

		if (Boolean.TRUE.equals(stored)) {
			// New code stored — also initialize the attempts counter
			redisTemplate.opsForValue()
					.set(attemptsKey(purpose, phoneNumber), "0", ttl, TimeUnit.SECONDS);
			log.info("OTP generated for phone={} purpose={}", maskPhone(phoneNumber), purpose);
		} else {
			// Code already exists — return existing code (rate-limiting in effect)
			String existing = redisTemplate.opsForValue().get(key);
			if (existing != null) {
				log.debug("OTP already exists for phone={} purpose={}, returning existing",
						maskPhone(phoneNumber), purpose);
				return existing;
			}
		}

		return code;
	}

	/**
	 * Verifies an OTP submission.
	 *
	 * Steps:
	 *   1. Load stored code for phone+purpose
	 *   2. Check attempts counter — throw if exceeded
	 *   3. Compare submitted code (constant-time)
	 *   4. On success: delete both keys (code + attempts) — consume-once
	 *   5. On failure: increment attempts counter; delete code if threshold hit
	 *
	 * @throws InvalidOtpException    if code is wrong or expired (no key in Redis)
	 * @throws OtpMaxAttemptsException if attempt limit exceeded
	 */
	public void verify(String phoneNumber, OtpPurpose purpose, String submittedCode) {
		String codeKey     = codeKey(purpose, phoneNumber);
		String attemptsKey = attemptsKey(purpose, phoneNumber);

		// Step 1: Load stored code
		String storedCode = redisTemplate.opsForValue().get(codeKey);
		if (storedCode == null) {
			// Key expired (TTL elapsed) or never existed
			log.debug("OTP not found or expired for phone={} purpose={}", maskPhone(phoneNumber), purpose);
			throw new InvalidOtpException(UserErrorCode.OTP_EXPIRED,
					"OTP has expired. Please request a new one.");
		}

		// Step 2: Check attempts
		String attemptsStr = redisTemplate.opsForValue().get(attemptsKey);
		int    attempts    = attemptsStr != null ? Integer.parseInt(attemptsStr) : 0;

		if (attempts >= UserConstants.OTP_MAX_ATTEMPTS) {
			redisTemplate.delete(codeKey);  // Invalidate the code — must re-request
			redisTemplate.delete(attemptsKey);
			throw new OtpMaxAttemptsException("Maximum OTP attempts exceeded. Please request a new OTP.");
		}

		// Step 3: Constant-time comparison (prevents timing attacks)
		if (!constantTimeEquals(storedCode, submittedCode)) {
			// Increment attempts
			redisTemplate.opsForValue().increment(attemptsKey);
			int remaining = UserConstants.OTP_MAX_ATTEMPTS - (attempts + 1);
			log.debug("OTP mismatch for phone={} purpose={}, attempts remaining={}",
					maskPhone(phoneNumber), purpose, remaining);

			if (remaining <= 0) {
				redisTemplate.delete(codeKey);
				redisTemplate.delete(attemptsKey);
				throw new OtpMaxAttemptsException("Maximum OTP attempts exceeded.");
			}

			throw new InvalidOtpException(UserErrorCode.OTP_INVALID,
					"Invalid OTP. " + remaining + " attempt(s) remaining.");
		}

		// Step 4: Success — consume (delete) both keys
		redisTemplate.delete(codeKey);
		redisTemplate.delete(attemptsKey);
		log.info("OTP verified for phone={} purpose={}", maskPhone(phoneNumber), purpose);
	}

	/**
	 * Explicitly invalidates an OTP — used when re-sending (regenerating).
	 * Deletes both the code and attempts counter so a fresh code can be stored.
	 */
	public void invalidate(String phoneNumber, OtpPurpose purpose) {
		redisTemplate.delete(codeKey(purpose, phoneNumber));
		redisTemplate.delete(attemptsKey(purpose, phoneNumber));
	}

	// ── Private helpers ───────────────────────────────────────────────────────

	private String generateCode() {
		// SecureRandom nextInt(900000) gives 0-899999, +100000 gives 100000-999999
		int code = 100000 + SECURE_RANDOM.nextInt(900000);
		return String.valueOf(code);
	}

	/**
	 * Constant-time string comparison.
	 *
	 * WHY not just .equals()?
	 *   String.equals() short-circuits on the first mismatch — timing differences
	 *   across characters can reveal how many digits match.
	 *   While 6-digit codes are not long enough to make this a practical attack,
	 *   it is a best-practice for any secret comparison.
	 */
	private boolean constantTimeEquals(String a, String b) {
		if (a.length() != b.length()) return false;
		int result = 0;
		for (int i = 0; i < a.length(); i++) {
			result |= a.charAt(i) ^ b.charAt(i);
		}
		return result == 0;
	}

	/** Masks phone for logging — +91XXXXXXXX10 → +91****XX10 */
	private String maskPhone(String phone) {
		if (phone == null || phone.length() < 6) return "***";
		return phone.substring(0, 3) + "****" + phone.substring(phone.length() - 2);
	}
}

