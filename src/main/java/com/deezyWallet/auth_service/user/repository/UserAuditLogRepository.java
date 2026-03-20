package com.deezyWallet.auth_service.user.repository;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.deezyWallet.auth_service.user.entity.UserAuditLog;
import com.deezyWallet.auth_service.user.enums.AuditAction;

/**
 * Audit log repository — append-only by design.
 *
 * This repository intentionally does NOT expose:
 *   - deleteById / deleteAll (inherited but should never be called)
 *   - Any @Modifying / UPDATE query
 *
 * The immutability contract is enforced at the entity level (no setters)
 * and reinforced here by having no mutation methods defined.
 *
 * In production, reinforce with DB-level permissions:
 *   REVOKE UPDATE, DELETE ON user_audit_log FROM 'wallet_app_user'@'%';
 *
 * findByUserId with Pageable:
 *   Audit logs grow over time. Always paginate — never load all for a user.
 *   Composite index (user_id, created_at DESC) makes this efficient.
 */
@Repository
public interface UserAuditLogRepository extends JpaRepository<UserAuditLog, Long> {

	Page<UserAuditLog> findByUserIdOrderByCreatedAtDesc(String userId, Pageable pageable);

	Page<UserAuditLog> findByUserIdAndActionOrderByCreatedAtDesc(
			String userId, AuditAction action, Pageable pageable);
}
