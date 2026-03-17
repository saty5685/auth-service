package com.deezyWallet.auth_service.user.entity;

import java.time.LocalDateTime;

import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EntityListeners;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import jakarta.persistence.Transient;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Persistent refresh token — stored as SHA-256 hash, never plaintext.
 *
 * LIFECYCLE:
 *   1. Login/Register: create record with tokenHash, expiresAt
 *   2. Refresh: lookup by hash → verify not revoked/expired → set revoked=true
 *                → create new record → return raw token to client
 *   3. Logout:  lookup by hash → set revoked=true
 *
 * WHY store hash instead of plaintext?
 *   A stolen DB backup should not yield active user sessions.
 *   Analogy: we hash passwords for the same reason.
 *   The client holds the raw token; the DB holds SHA-256(token).
 *   Verification: SHA-256(incoming token) == stored tokenHash
 *
 * WHY per-device support (userAgent)?
 *   A user can have multiple devices (phone + laptop + tablet).
 *   Each gets its own refresh token row.
 *   Admin can view and revoke specific device sessions.
 *
 * Rotation policy: every use of a refresh token creates a new one
 *   and revokes the old. If a refresh token is used twice (replay attack),
 *   the second use will fail with TOKEN_REVOKED.
 */
@Entity
@Table(
		name = "refresh_tokens",
		indexes = {
				@Index(name = "idx_refresh_user_id",    columnList = "user_id"),
				@Index(name = "idx_refresh_token_hash", columnList = "token_hash")
		}
)
@EntityListeners(AuditingEntityListener.class)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RefreshToken {

	@Id
	@Column(length = 36, updatable = false, nullable = false)
	private String id;

	@ManyToOne(fetch = FetchType.LAZY)
	@JoinColumn(name = "user_id", nullable = false)
	private User user;

	/** SHA-256 hex digest of the raw token. Never the raw token itself. */
	@Column(name = "token_hash", nullable = false, unique = true, length = 64)
	private String tokenHash;

	/** IPv4 or IPv6 address of the creating request */
	@Column(name = "ip_address", length = 45)
	private String ipAddress;

	@Column(name = "user_agent")
	private String userAgent;

	@Column(name = "expires_at", nullable = false)
	private LocalDateTime expiresAt;

	@Column(name = "revoked", nullable = false)
	@Builder.Default
	private boolean revoked = false;

	@CreatedDate
	@Column(name = "created_at", updatable = false, nullable = false)
	private LocalDateTime createdAt;

	@Transient
	public boolean isExpired() {
		return LocalDateTime.now().isAfter(expiresAt);
	}

	@Transient
	public boolean isValid() {
		return !revoked && !isExpired();
	}
}
