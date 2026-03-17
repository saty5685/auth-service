package com.deezyWallet.auth_service.user.entity;

import java.time.LocalDateTime;

import com.deezyWallet.auth_service.user.enums.AuditAction;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * Immutable audit log — every sensitive action on a user account.
 *
 * IMMUTABILITY CONTRACT:
 *   This entity has NO setters. Once created, it is never updated.
 *   The repository exposes only save() and find*() — no update or delete.
 *   This is enforced at the code level (no @Setter, no @Data) and should
 *   be reinforced by DB-level permissions in production (REVOKE UPDATE on
 *   user_audit_log FROM wallet_app_user).
 *
 * WHY not use Spring Data Auditing (@CreatedDate)?
 *   AuditingEntityListener requires @Setter or @Data to populate @CreatedDate.
 *   Since we're intentionally immutable, we set createdAt in the constructor
 *   / builder and make the column non-updatable.
 *
 * metadata field:
 *   JSON blob for action-specific context.
 *   LOGIN_SUCCESS  → {"ip": "192.168.1.1", "device": "iPhone"}
 *   PASSWORD_CHANGED → {"changedFrom": "ip", "method": "self"}
 *   ACCOUNT_SUSPENDED → {"reason": "fraud_report_42", "adminId": "uuid"}
 *   Stored as TEXT, parsed by consumers as needed.
 */
@Entity
@Table(
		name = "user_audit_log",
		indexes = {
				@Index(name = "idx_audit_user_time", columnList = "user_id, created_at")
		}
)
@Getter  // Only getters — no setters
@NoArgsConstructor(access = AccessLevel.PROTECTED) // JPA needs no-arg constructor
@AllArgsConstructor
@Builder
public class UserAuditLog {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	/** The user this action was performed on (or by) */
	@Column(name = "user_id", nullable = false, length = 36)
	private String userId;

	@Enumerated(EnumType.STRING)
	@Column(nullable = false, length = 50)
	private AuditAction action;

	/** JSON metadata — action-specific context. May be null for simple events. */
	@Column(columnDefinition = "TEXT")
	private String metadata;

	/** IPv4 or IPv6 of the originating request */
	@Column(name = "ip_address", length = 45)
	private String ipAddress;

	@Column(name = "created_at", updatable = false, nullable = false)
	private LocalDateTime createdAt;

	@PrePersist
	protected void prePersist() {
		if (this.createdAt == null) {
			this.createdAt = LocalDateTime.now();
		}
	}
}
