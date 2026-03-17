package com.deezyWallet.auth_service.user.constants;

/**
 * Compile-time constants for User & Identity Service.
 *
 * WHY constants instead of @Value in every class?
 *   Magic strings scattered across classes create maintenance risk.
 *   A single source of truth here means a Redis key prefix change is
 *   a one-line edit, not a grep-and-replace.
 *
 * WHY not store these in application.yml?
 *   These are structural constants — part of the code contract, not
 *   deployment configuration. They should not vary between environments.
 *   Configuration (timeouts, feature flags, external URLs) belongs in YAML.
 *   Structural constants (key prefixes, role names, limits) belong here.
 */
public final class UserConstants {

	private UserConstants() { /* utility class — no instantiation */ }

	// ── Redis key prefixes ────────────────────────────────────────────────────
	// Pattern: {service}:{entity}:{identifier}
	// Consistent naming prevents key collisions if services share a Redis instance.

	/** OTP storage. Full key: otp:{purpose}:{phoneNumber} */
	public static final String REDIS_OTP_PREFIX      = "user:otp:";

	/** Active session (maps sessionId → userId). Full key: user:session:{sessionId} */
	public static final String REDIS_SESSION_PREFIX  = "user:session:";

	/** Access-token blacklist (logout). Full key: user:blacklist:{jti} */
	public static final String REDIS_BLACKLIST_PREFIX = "user:blacklist:";

	/** MFA pending state (between password-ok and OTP-ok). Full key: user:mfa_pending:{userId} */
	public static final String REDIS_MFA_PENDING_PREFIX = "user:mfa_pending:";


	// ── Role names ────────────────────────────────────────────────────────────
	// Must match roles.name column values and JWT claim strings.
	// Spring Security expects "ROLE_" prefix when using hasRole(), but the
	// raw string (without prefix) is what we store in DB and JWT claims.

	public static final String ROLE_USER             = "ROLE_USER";
	public static final String ROLE_MERCHANT         = "ROLE_MERCHANT";
	public static final String ROLE_ADMIN            = "ROLE_ADMIN";
	public static final String ROLE_INTERNAL_SERVICE = "ROLE_INTERNAL_SERVICE";


	// ── JWT claim keys ────────────────────────────────────────────────────────
	public static final String JWT_CLAIM_EMAIL       = "email";
	public static final String JWT_CLAIM_ROLES       = "roles";
	public static final String JWT_CLAIM_PHONE       = "phone";
	public static final String JWT_CLAIM_KYC_STATUS  = "kycStatus";


	// ── Account lockout ───────────────────────────────────────────────────────
	/** Number of consecutive failed logins before temporary lockout */
	public static final int    MAX_FAILED_LOGIN_ATTEMPTS = 5;

	/** Duration of the first lockout in minutes */
	public static final int    LOCKOUT_DURATION_MINUTES  = 15;


	// ── Password rules ────────────────────────────────────────────────────────
	public static final int    PASSWORD_MIN_LENGTH        = 8;
	public static final int    PASSWORD_MAX_LENGTH        = 128;
	// Regex enforced at DTO validation layer:
	// At least 1 uppercase, 1 lowercase, 1 digit, 1 special char
	public static final String PASSWORD_PATTERN =
			"^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,128}$";


	// ── OTP ───────────────────────────────────────────────────────────────────
	public static final int    OTP_LENGTH               = 6;
	/** Max OTP verification attempts before the OTP is invalidated */
	public static final int    OTP_MAX_ATTEMPTS         = 3;


	// ── Kafka topics ──────────────────────────────────────────────────────────
	public static final String TOPIC_USER_EVENTS        = "user.events";

	// ── API paths ─────────────────────────────────────────────────────────────
	public static final String API_AUTH_BASE            = "/api/v1/auth";
	public static final String API_USER_BASE            = "/api/v1/users";
	public static final String API_ADMIN_BASE           = "/api/v1/admin/users";
	public static final String API_INTERNAL_BASE        = "/internal/v1/users";
	public static final String ACTUATOR_HEALTH          = "/actuator/health";


	// ── MFA ───────────────────────────────────────────────────────────────────
	/** TOTP window tolerance — how many 30s windows to accept (1 = ±30s) */
	public static final int    TOTP_WINDOW              = 1;
	public static final String TOTP_ISSUER              = "DigitalWallet";
	/** MFA pending state TTL — user has this long to complete MFA after password */
	public static final int    MFA_PENDING_TTL_SECONDS  = 300; // 5 minutes
}

