package com.deezyWallet.auth_service.user.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import lombok.Data;

/**
 * Strongly-typed binding for jwt.* properties in application.yml.
 *
 * WHY @ConfigurationProperties instead of @Value?
 *   @Value binds one property at a time. @ConfigurationProperties binds a
 *   whole namespace. When we add a new JWT property, it's one field here
 *   vs a new @Value annotation scattered across 2-3 service classes.
 *   Also enables validation via @Validated on the class.
 *
 * Separate expiry values for access and refresh tokens:
 *   accessExpiryMs  = 15 minutes  (short — limits blast radius if stolen)
 *   refreshExpiryMs = 7 days      (long — persisted in DB with revocation)
 *
 * secret must be Base64-encoded and at least 512 bits (64 bytes) for HS512.
 */
@Data
@Component
@ConfigurationProperties(prefix = "jwt")
public class JwtProperties {
	/** Base64-encoded HMAC-SHA512 secret — minimum 64 bytes decoded */
	private String secret;

	/** Access token lifetime in milliseconds. Default: 900_000 (15 min) */
	private long accessExpiryMs = 900_000L;

	/** Refresh token lifetime in milliseconds. Default: 604_800_000 (7 days) */
	private long refreshExpiryMs = 604_800_000L;

	/** Service-to-service token lifetime in milliseconds. Default: 86_400_000 (24 hours) */
	private long serviceExpiryMs = 86_400_000L;

	/** Token issuer claim — must match across all services for validation */
	private String issuer = "digital-wallet-platform";
}
