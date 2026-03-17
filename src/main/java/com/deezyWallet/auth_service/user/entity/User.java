package com.deezyWallet.auth_service.user.entity;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;

import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import com.deezyWallet.auth_service.user.enums.KycStatus;
import com.deezyWallet.auth_service.user.enums.UserStatus;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EntityListeners;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinTable;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.Table;
import jakarta.persistence.Transient;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Central user entity — represents a registered wallet user.
 *
 * DESIGN DECISIONS:
 *
 * UUID primary key (VARCHAR(36) in MySQL):
 *   Non-sequential → prevents user count enumeration from IDs.
 *   DEFAULT (UUID()) set in Flyway migration, not in app code.
 *   WHY not @GeneratedValue(IDENTITY)?
 *   AUTO_INCREMENT leaks user count (user #1042 means ~1041 others exist).
 *   UUID is opaque — no information about total users.
 *
 * passwordHash — BCrypt only, cost factor 12. Never stored plain.
 *   The entity never exposes a setter that accepts a plain password.
 *   Encoding is done in AuthService before calling the setter.
 *
 * mfaSecret — TOTP secret, AES-256 encrypted at rest.
 *   The column stores encrypted bytes; decryption happens in MfaService.
 *   Even with DB access, the TOTP secret is not immediately usable.
 *
 * failedLoginAttempts + lockedUntil — login lockout in DB (not Redis).
 *   Survives service restarts and Redis failures.
 *   An attacker cannot clear the lockout by waiting for Redis TTL expiry
 *   or by causing a Redis restart.
 *
 * @ManyToMany EAGER for roles:
 *   Roles are needed on every authenticated request (for JWT claim population).
 *   LAZY would require an open session, which is not available in JwtAuthFilter.
 *   The set is tiny (1-2 roles per user) so EAGER is acceptable here.
 *
 * @EntityListeners(AuditingEntityListener.class):
 *   Enables @CreatedDate and @LastModifiedDate auto-population.
 *   Requires @EnableJpaAuditing on a @Configuration class.
 */
@Entity
@Table(
		name = "users",
		indexes = {
				@Index(name = "idx_users_email",  columnList = "email"),
				@Index(name = "idx_users_phone",  columnList = "phone_number"),
				@Index(name = "idx_users_status", columnList = "status")
		}
)
@EntityListeners(AuditingEntityListener.class)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class User {

	@Id
	@Column(name = "id", length = 36, updatable = false, nullable = false)
	private String id;  // Set by Flyway DEFAULT (UUID()) or generated in service

	@Column(nullable = false, unique = true, length = 100)
	private String email;

	@Column(name = "phone_number", nullable = false, unique = true, length = 20)
	private String phoneNumber;

	@Column(name = "password_hash", nullable = false)
	private String passwordHash;  // BCrypt hash, cost=12

	@Column(name = "first_name", nullable = false, length = 60)
	private String firstName;

	@Column(name = "last_name", nullable = false, length = 60)
	private String lastName;

	@Enumerated(EnumType.STRING)
	@Column(nullable = false, length = 20)
	@Builder.Default
	private UserStatus status = UserStatus.PENDING;

	@Enumerated(EnumType.STRING)
	@Column(name = "kyc_status", nullable = false, length = 20)
	@Builder.Default
	private KycStatus kycStatus = KycStatus.UNVERIFIED;

	@ManyToMany(fetch = FetchType.EAGER)
	@JoinTable(
			name = "user_roles",
			joinColumns        = @JoinColumn(name = "user_id"),
			inverseJoinColumns = @JoinColumn(name = "role_id")
	)
	@Builder.Default
	private Set<Role> roles = new HashSet<>();

	@Column(name = "mfa_enabled", nullable = false)
	@Builder.Default
	private boolean mfaEnabled = false;

	/**
	 * TOTP secret — AES-256 encrypted before storage.
	 * NULL until MFA setup is confirmed by the user.
	 */
	@Column(name = "mfa_secret")
	private String mfaSecret;

	// ── Login lockout (in DB, not Redis) ──────────────────────────────────────

	@Column(name = "failed_login_attempts", nullable = false)
	@Builder.Default
	private int failedLoginAttempts = 0;

	/** NULL unless currently locked. Lockout expires when this timestamp passes. */
	@Column(name = "locked_until")
	private LocalDateTime lockedUntil;

	@Column(name = "last_login_at")
	private LocalDateTime lastLoginAt;

	/** Stored as VARCHAR(45) to support both IPv4 and IPv6 */
	@Column(name = "last_login_ip", length = 45)
	private String lastLoginIp;

	@CreatedDate
	@Column(name = "created_at", updatable = false, nullable = false)
	private LocalDateTime createdAt;

	@LastModifiedDate
	@Column(name = "updated_at", nullable = false)
	private LocalDateTime updatedAt;

	// ── Business logic helpers ────────────────────────────────────────────────

	/**
	 * Returns true if this account is currently locked due to failed attempts.
	 * Lockout is time-based — once lockedUntil passes, the account auto-unlocks.
	 */
	@Transient
	public boolean isLoginLocked() {
		return lockedUntil != null && LocalDateTime.now().isBefore(lockedUntil);
	}

	/**
	 * Records a failed login attempt. Locks account after threshold.
	 * Must be called inside a @Transactional method — changes are not saved until commit.
	 */
	@Transient
	public void recordFailedLogin() {
		this.failedLoginAttempts++;
	}

	@Transient
	public void resetFailedLoginAttempts() {
		this.failedLoginAttempts = 0;
		this.lockedUntil = null;
	}

	@Transient
	public void applyLockout(int durationMinutes) {
		this.lockedUntil = LocalDateTime.now().plusMinutes(durationMinutes);
	}
}
