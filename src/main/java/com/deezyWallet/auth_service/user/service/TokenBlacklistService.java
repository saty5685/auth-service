package com.deezyWallet.auth_service.user.service;

import java.util.concurrent.TimeUnit;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import com.deezyWallet.auth_service.user.constants.UserConstants;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Access token blacklisting — invalidates tokens on logout before natural expiry.
 *
 * PROBLEM: JWT access tokens are stateless and self-validating.
 *   Once issued, they're valid until expiry (15 minutes).
 *   If a user logs out, the access token is still cryptographically valid.
 *   An attacker who captured the token can use it for up to 15 more minutes.
 *
 * SOLUTION: Blacklist by JTI (JWT ID)
 *   Every access token has a unique `jti` claim (UUID).
 *   On logout, we store the jti in Redis with a TTL equal to the token's
 *   remaining lifetime. JwtAuthFilter checks the blacklist on every request.
 *
 * KEY DESIGN:
 *   user:blacklist:{jti}  → "1"  (value doesn't matter — existence is the signal)
 *   TTL = remaining token lifetime in seconds
 *
 * After the token's natural expiry, the Redis key expires automatically —
 * no cleanup needed. The blacklist is eventually self-cleaning.
 *
 * WHY not blacklist in DB?
 *   Every API request would hit the DB for a blacklist check — unacceptable latency.
 *   Redis O(1) GET is sub-millisecond.
 *
 * FAIL BEHAVIOUR:
 *   If Redis is unreachable during blacklist check → log warning + ALLOW request.
 *   Rationale: A Redis outage should not log out all users or block all API calls.
 *   The 15-minute window is short enough that this is an acceptable trade-off.
 *   Security-first teams may reverse this (deny on error) — document the choice.
 *
 * SCALE CONSIDERATION:
 *   Blacklist size = (active users) × (logout rate) × (access token TTL / cleanup interval)
 *   At 1M users, 10% daily logout, 15min TTL → ~1M × 0.10 / (24*4) ≈ ~1041 keys at any time.
 *   Each key is ~50 bytes. Total memory: <100KB. Completely negligible.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class TokenBlacklistService {

	private final RedisTemplate<String, String> redisTemplate;

	/**
	 * Adds a token's JTI to the blacklist.
	 *
	 * @param jti           the JWT ID from the token's `jti` claim
	 * @param ttlSeconds    remaining lifetime of the token in seconds
	 */
	public void blacklist(String jti, long ttlSeconds) {
		if (jti == null || ttlSeconds <= 0) {
			log.debug("Skipping blacklist: jti={} ttl={}", jti, ttlSeconds);
			return;
		}
		try {
			redisTemplate.opsForValue()
					.set(blacklistKey(jti), "1", ttlSeconds, TimeUnit.SECONDS);
			log.debug("Access token blacklisted: jti={} ttl={}s", jti, ttlSeconds);
		} catch (Exception e) {
			// Non-fatal — token will expire naturally in ttlSeconds
			log.warn("Failed to blacklist token jti={}: {}", jti, e.getMessage());
		}
	}

	/**
	 * Returns true if the given JTI is on the blacklist.
	 *
	 * Called by JwtAuthFilter on every authenticated request.
	 * Fail-open: returns false (allow) on Redis errors to prevent service outage.
	 */
	public boolean isBlacklisted(String jti) {
		if (jti == null) return false;
		try {
			return Boolean.TRUE.equals(redisTemplate.hasKey(blacklistKey(jti)));
		} catch (Exception e) {
			// Fail-open: Redis down → allow (short-lived risk vs complete auth outage)
			log.warn("Redis error during blacklist check for jti={}: {}", jti, e.getMessage());
			return false;
		}
	}

	private String blacklistKey(String jti) {
		return UserConstants.REDIS_BLACKLIST_PREFIX + jti;
	}
}
