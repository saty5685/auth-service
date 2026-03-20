package com.deezyWallet.auth_service.user.repository;

import java.time.LocalDateTime;
import java.util.Optional;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.deezyWallet.auth_service.user.entity.User;
import com.deezyWallet.auth_service.user.enums.UserStatus;

/**
 * User repository.
 *
 * METHOD DESIGN DECISIONS:
 *
 * findByEmail vs findById:
 *   Login uses findByEmail (credential lookup by unique column).
 *   All subsequent requests use findById (JWT sub claim is the UUID).
 *   Both are indexed. findByEmail is the most frequent read in the service.
 *
 * existsByEmail / existsByPhoneNumber:
 *   Used for duplicate-check during registration.
 *   SELECT COUNT(*) internally — far cheaper than loading the full entity
 *   just to check existence. No need to load roles (EAGER) for a boolean check.
 *
 * updateLastLogin — @Modifying native UPDATE:
 *   Called after every successful login. If we load the full User, set two
 *   fields, and save(), Hibernate issues UPDATE with ALL columns — wasteful
 *   and a risk of overwriting concurrent changes (e.g. a parallel failedAttempts
 *   increment). A targeted UPDATE with two columns is safer and faster.
 *
 * findAllByStatus (paginated):
 *   Admin "list users" endpoint. Always paginated — never SELECT * on users table.
 *   status index (idx_users_status) makes this efficient.
 */
@Repository
public interface UserRepository extends JpaRepository<User, String> {

	// ── Lookup ────────────────────────────────────────────────────────────────

	Optional<User> findByEmail(String email);

	Optional<User> findByPhoneNumber(String phoneNumber);

	// ── Existence checks (for duplicate validation) ───────────────────────────

	boolean existsByEmail(String email);

	boolean existsByPhoneNumber(String phoneNumber);

	// ── Admin queries ─────────────────────────────────────────────────────────

	Page<User> findAllByStatus(UserStatus status, Pageable pageable);

	Page<User> findAll(Pageable pageable);

	// ── Targeted updates (avoid full-entity save on hot paths) ────────────────

	/**
	 * Updates lastLoginAt and lastLoginIp after successful authentication.
	 *
	 * WHY @Modifying(clearAutomatically = true)?
	 *   After a bulk UPDATE via JPQL, the first-level cache (EntityManager) may
	 *   still hold a stale User entity. clearAutomatically = true clears it,
	 *   ensuring the next read for this entity reflects the updated values.
	 *   Without this, a subsequent findById in the same transaction would return
	 *   the cached (stale) entity.
	 */
	@Modifying(clearAutomatically = true)
	@Query("UPDATE User u SET u.lastLoginAt = :loginAt, u.lastLoginIp = :ip," +
			" u.failedLoginAttempts = 0, u.lockedUntil = NULL WHERE u.id = :userId")
	void updateLastLoginAndResetLockout(@Param("userId") String userId,
			@Param("loginAt") LocalDateTime loginAt,
			@Param("ip")      String ip);

	/**
	 * Increments failed login attempts — called after each bad password.
	 * Deliberately a targeted UPDATE — concurrent increments from multiple
	 * request threads converge correctly. Using user.setFailed... + save()
	 * would cause lost-update race conditions.
	 */
	@Modifying(clearAutomatically = true)
	@Query("UPDATE User u SET u.failedLoginAttempts = u.failedLoginAttempts + 1 WHERE u.id = :userId")
	void incrementFailedLoginAttempts(@Param("userId") String userId);

	/**
	 * Applies lockout — sets lockedUntil after threshold exceeded.
	 */
	@Modifying(clearAutomatically = true)
	@Query("UPDATE User u SET u.lockedUntil = :lockedUntil WHERE u.id = :userId")
	void applyLockout(@Param("userId") String userId,
			@Param("lockedUntil") LocalDateTime lockedUntil);

	/**
	 * Updates KYC status — called by KYC event consumer.
	 * Targeted update prevents overwriting unrelated fields.
	 */
	@Modifying(clearAutomatically = true)
	@Query("UPDATE User u SET u.kycStatus = :kycStatus WHERE u.id = :userId")
	void updateKycStatus(@Param("userId") String userId,
			@Param("kycStatus") com.deezyWallet.auth_service.user.enums.KycStatus kycStatus);
}
