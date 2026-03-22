package com.deezyWallet.auth_service.user.security;

import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

import javax.crypto.SecretKey;

import org.springframework.stereotype.Service;

import com.deezyWallet.auth_service.user.config.JwtProperties;
import com.deezyWallet.auth_service.user.constants.UserConstants;
import com.deezyWallet.auth_service.user.entity.User;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * JWT issuer and validator — owned exclusively by User & Identity Service.
 *
 * This service is the ONLY issuer of JWTs in the platform.
 * All other services (Wallet, Transaction, etc.) use a resource-server
 * pattern — they validate but never issue.
 *
 * TOKEN ANATOMY (access token):
 * ─────────────────────────────
 *   sub         → userId (UUID string)
 *   email       → user's email
 *   phone       → user's phone number
 *   roles       → ["ROLE_USER"] or ["ROLE_ADMIN"] etc.
 *   kycStatus   → "VERIFIED" etc. (denormalized for Transaction Service)
 *   jti         → UUID — unique token ID, used for blacklisting on logout
 *   iat         → issued-at timestamp
 *   exp         → expiry timestamp
 *   iss         → "digital-wallet-platform"
 *
 * WHY embed kycStatus in the token?
 *   Transaction Service needs KYC status to allow/deny high-value txns.
 *   Embedding it avoids a sync HTTP call from Transaction → User on every txn.
 *   The cost: KYC status change takes up to accessExpiryMs (15 min) to propagate.
 *   This is acceptable — KYC verification is not an instant process anyway.
 *
 * REFRESH TOKEN:
 * ──────────────
 *   Not a JWT — just a cryptographically random UUID.
 *   The raw token is returned to the client once, never stored in DB.
 *   DB stores SHA-256(token) so a DB breach doesn't leak valid tokens.
 *   On use: lookup by hash → verify not revoked/expired → issue new pair → revoke old.
 *
 * WHY store refresh token as a hash?
 *   Analogy: same reason passwords are hashed.
 *   A stolen DB backup should not yield active sessions.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class JwtService {

	private final JwtProperties jwtProperties;

	private SecretKey signingKey() {
		byte[] keyBytes = Decoders.BASE64.decode(jwtProperties.getSecret());
		return Keys.hmacShaKeyFor(keyBytes);
	}

	/**
	 * Issues an access token for the given user.
	 * Embeds all claims needed for downstream service authorization.
	 */
	public String generateAccessToken(User user) {
		List<String> roles = user.getRoles().stream()
				.map(role -> role.getName())
				.collect(Collectors.toList());

		return Jwts.builder()
				.subject(user.getId())
				.issuer(jwtProperties.getIssuer())
				.claim(UserConstants.JWT_CLAIM_EMAIL,      user.getEmail())
				.claim(UserConstants.JWT_CLAIM_PHONE,      user.getPhoneNumber())
				.claim(UserConstants.JWT_CLAIM_ROLES,      roles)
				.claim(UserConstants.JWT_CLAIM_KYC_STATUS, user.getKycStatus().name())
				.id(UUID.randomUUID().toString())  // jti — used for blacklisting
				.issuedAt(new Date())
				.expiration(new Date(System.currentTimeMillis() + jwtProperties.getAccessExpiryMs()))
				.signWith(signingKey(), SignatureAlgorithm.HS512)
				.compact();
	}

	/**
	 * Generates a cryptographically random refresh token (plain UUID, not a JWT).
	 * The caller is responsible for hashing and persisting it.
	 */
	public String generateRefreshToken() {
		return UUID.randomUUID().toString() + "-" + UUID.randomUUID().toString();
		// Double UUID: 256 bits of entropy — far exceeds NIST SP 800-63B requirements
	}

	/**
	 * Validates and extracts all claims from a token.
	 *
	 * @throws JwtException on invalid signature, expired token, or malformed input.
	 *   Callers should catch JwtException and translate to their domain exception.
	 */
	public Claims validateAndExtract(String token) {
		return Jwts.parser()
				.verifyWith(signingKey())
				.build()
				.parseSignedClaims(token)
				.getPayload();
	}

	/**
	 * Extracts the jti (JWT ID) from a token WITHOUT full validation.
	 * Used for blacklist entry on logout — we still need the jti even
	 * if the token is about to be invalidated.
	 *
	 * WARNING: Do not use this for authorization decisions — token is not validated.
	 */
	public String extractJtiUnsafe(String token) {
		try {
			// Parse without signature verification — body is still readable
			int i = token.lastIndexOf('.');
			String withoutSignature = token.substring(0, i + 1);
			return (String) Jwts.parser()
					.unsecured()
					.build()
					.parseUnsecuredClaims(withoutSignature)
					.getPayload()
					.getId();
		} catch (Exception e) {
			log.warn("Could not extract jti from token for blacklisting: {}", e.getMessage());
			return null;
		}
	}

	/**
	 * Returns the remaining TTL in seconds for a token.
	 * Used when adding a token to the blacklist — we only need to keep it
	 * blacklisted until its natural expiry.
	 */
	public long getRemainingTtlSeconds(Claims claims) {
		long expiryMs = claims.getExpiration().getTime();
		long nowMs    = System.currentTimeMillis();
		return Math.max(0, (expiryMs - nowMs) / 1000);
	}

	/**
	 * Returns the refresh token lifetime in seconds.
	 * Used by AuthService when setting RefreshToken.expiresAt.
	 */
	public long getRefreshExpirySeconds() {
		return jwtProperties.getRefreshExpiryMs() / 1000;
	}
}
 
