package com.deezyWallet.auth_service.user.repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.deezyWallet.auth_service.user.entity.RefreshToken;

/**
 * Refresh token repository.
 *
 * LOOKUP STRATEGY:
 *   All lookups are by tokenHash (SHA-256 hex of the raw token).
 *   The raw token is never stored — only the hash.
 *   The client sends the raw token; the service hashes it and looks it up.
 *
 * findByTokenHashAndRevokedFalse:
 *   The most critical query — validates an incoming refresh token.
 *   Both conditions are needed: hash must match AND token must not be revoked.
 *   Checking expiresAt in application code (not DB) for clarity — but an
 *   alternative is to add AND expires_at > NOW() to the query.
 *
 * revokeAllByUserId:
 *   Called on logout-all-devices or account suspension.
 *   Bulk UPDATE more efficient than loading all tokens and saving one-by-one.
 *
 * deleteExpiredTokens:
 *   Scheduled cleanup job — prevents the table growing unboundedly.
 *   Only deletes revoked or expired tokens — active tokens are never deleted.
 */
@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, String> {

	Optional<RefreshToken> findByTokenHash(String tokenHash);

	Optional<RefreshToken> findByTokenHashAndRevokedFalse(String tokenHash);

	List<RefreshToken> findAllByUser_Id(String userId);

	List<RefreshToken> findAllByUser_IdAndRevokedFalse(String userId);

	/**
	 * Revokes all active refresh tokens for a user.
	 * Called on: logout-all, account suspension, password change.
	 */
	@Modifying(clearAutomatically = true)
	@Query("UPDATE RefreshToken t SET t.revoked = true WHERE t.user.id = :userId AND t.revoked = false")
	int revokeAllByUserId(@Param("userId") String userId);

	/**
	 * Cleanup job — deletes tokens that are either expired or already revoked.
	 * Run periodically (e.g. nightly) via @Scheduled.
	 *
	 * WHY delete only expired+revoked?
	 *   Revoked tokens might still be within their 7-day window but were
	 *   explicitly invalidated. We keep them for the audit trail until
	 *   they also expire. Only deleting when BOTH conditions are true.
	 */
	@Modifying
	@Query("DELETE FROM RefreshToken t WHERE t.expiresAt < :cutoff AND t.revoked = true")
	int deleteExpiredAndRevokedBefore(@Param("cutoff") LocalDateTime cutoff);
}
