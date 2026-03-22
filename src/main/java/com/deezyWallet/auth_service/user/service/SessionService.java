package com.deezyWallet.auth_service.user.service;

import java.util.concurrent.TimeUnit;

import org.springframework.data.redis.core.Cursor;
import org.springframework.data.redis.core.RedisCallback;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ScanOptions;
import org.springframework.stereotype.Service;

import com.deezyWallet.auth_service.user.config.JwtProperties;
import com.deezyWallet.auth_service.user.constants.UserConstants;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Redis-backed session management for active login sessions.
 *
 * WHAT IS A SESSION HERE?
 *   Not an HttpSession. A session is a Redis entry that maps:
 *     user:session:{sessionId} → userId
 *   with a TTL equal to the refresh token's expiry (7 days).
 *
 * RELATIONSHIP WITH REFRESH TOKENS:
 *   Both the DB refresh_tokens row and this Redis session key are
 *   created together at login and destroyed together at logout.
 *
 *   DB row  → authoritative record, used for token rotation validation
 *   Redis   → fast lookup for "is this user currently active?"
 *             and for "how many active sessions does this user have?"
 *
 * WHY Redis for sessions at all if we already have the DB token?
 *   Fast session count queries without hitting the DB.
 *   Instant invalidation: DEL key is O(1) vs UPDATE refresh_tokens + possible
 *   cache invalidation in a future caching layer.
 *   Admin dashboards can query active session counts without DB joins.
 *
 * SESSION ID:
 *   Not the refresh token itself (that's a secret).
 *   A separate UUID created at login, returned in the AuthResponse if needed.
 *   In our current design the sessionId == SHA-256(refreshToken) so
 *   they share the same lookup key — consistent, no extra field needed.
 *
 * FAIL-OPEN on Redis errors:
 *   Session operations are best-effort. If Redis is down:
 *   - saveSession failure → log warning, don't block login
 *   - isSessionActive failure → return false (conservative — re-auth required)
 *   - deleteSession failure → log warning (token revocation in DB is the real guard)
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class SessionService {

	private final RedisTemplate<String, String> redisTemplate;
	private final JwtProperties jwtProperties;

	/** Derives session TTL from JwtProperties.refreshExpiryMs to stay in sync. */
	private long sessionTtlSeconds() {
		return jwtProperties.getRefreshExpiryMs() / 1000;
	}

	// ── Public API ────────────────────────────────────────────────────────────

	/**
	 * Stores a session entry in Redis after successful login.
	 *
	 * @param userId      the authenticated user's ID
	 * @param sessionId   typically SHA-256(refreshToken) — shared key with DB row
	 * @param ipAddress   the request IP for audit (stored as value metadata)
	 */
	public void saveSession(String userId, String sessionId, String ipAddress) {
		try {
			String key   = sessionKey(sessionId);
			String value = userId + "|" + (ipAddress != null ? ipAddress : "unknown");
			redisTemplate.opsForValue().set(key, value, sessionTtlSeconds(), TimeUnit.SECONDS);
			log.debug("Session saved for userId={} sessionId={}", userId, sessionId);
		} catch (Exception e) {
			// Non-fatal — DB refresh token is the authoritative record
			log.warn("Failed to save session in Redis for userId={}: {}", userId, e.getMessage());
		}
	}

	/**
	 * Checks whether a session is currently active.
	 * Returns false conservatively on Redis errors.
	 */
	public boolean isSessionActive(String sessionId) {
		try {
			return Boolean.TRUE.equals(redisTemplate.hasKey(sessionKey(sessionId)));
		} catch (Exception e) {
			log.warn("Redis error checking session {}: {}", sessionId, e.getMessage());
			return false; // Conservative: force re-auth if Redis is down
		}
	}

	/**
	 * Deletes a session on logout.
	 * Best-effort — DB token revocation is the authoritative invalidation.
	 */
	public void deleteSession(String sessionId) {
		try {
			redisTemplate.delete(sessionKey(sessionId));
			log.debug("Session deleted for sessionId={}", sessionId);
		} catch (Exception e) {
			log.warn("Failed to delete session {} from Redis: {}", sessionId, e.getMessage());
		}
	}

	/**
	 * Deletes all sessions for a user — used on suspend/account closure.
	 *
	 * WHY SCAN instead of a set of session IDs?
	 *   We don't maintain a secondary index (userId → sessionIds) in Redis.
	 *   SCAN with a pattern is the standard approach for key enumeration.
	 *   Pattern: user:session:* then filter by value prefix userId|
	 *
	 *   In practice, a user has at most a handful of active sessions (phone +
	 *   laptop + tablet). SCAN overhead is minimal.
	 *
	 * WARNING: This is O(N) on the number of Redis keys matching the pattern.
	 *   If Redis keyspace is very large, SCAN can be slow.
	 *   Production hardening: maintain a Redis Set per user of their session IDs.
	 */
	public void deleteAllSessionsForUser(String userId) {
		try {
			// Scan all session keys, delete those belonging to this user
			redisTemplate.execute((RedisCallback<Void>) connection -> {
				ScanOptions options = ScanOptions.scanOptions()
						.match(UserConstants.REDIS_SESSION_PREFIX + "*")
						.count(100)
						.build();
				Cursor<byte[]> cursor = connection.scan(options);
				while (cursor.hasNext()) {
					byte[] keyBytes = cursor.next();
					String key   = new String(keyBytes);
					String value = redisTemplate.opsForValue().get(key);
					if (value != null && value.startsWith(userId + "|")) {
						redisTemplate.delete(key);
					}
				}
				try { cursor.close(); } catch (Exception ignored) {}
				return null;
			});
			log.info("All sessions deleted for userId={}", userId);
		} catch (Exception e) {
			log.warn("Failed to delete all sessions for userId={}: {}", userId, e.getMessage());
		}
	}

	// ── Private helpers ───────────────────────────────────────────────────────

	private String sessionKey(String sessionId) {
		return UserConstants.REDIS_SESSION_PREFIX + sessionId;
	}
}
