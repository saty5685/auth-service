package com.deezyWallet.auth_service.user.service;

import java.util.Map;

import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import com.deezyWallet.auth_service.user.entity.UserAuditLog;
import com.deezyWallet.auth_service.user.enums.AuditAction;
import com.deezyWallet.auth_service.user.repository.UserAuditLogRepository;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Immutable audit log writer.
 *
 * WHY @Async?
 *   Audit writes are fire-and-forget. Login should not be slowed by an
 *   INSERT into the audit log. @Async dispatches to a thread pool and
 *   returns immediately to the caller.
 *
 *   Requires @EnableAsync on a @Configuration class.
 *
 * WHY Propagation.REQUIRES_NEW?
 *   The audit entry must be committed even if the outer transaction rolls back.
 *   Example: login FAILED (outer tx rolls back) → we still want an audit entry
 *   for the failed attempt. REQUIRES_NEW opens a separate transaction that
 *   commits independently of the caller's transaction.
 *
 * WHY async + new transaction together?
 *   @Async runs in a different thread → no transaction context from the caller.
 *   REQUIRES_NEW starts a fresh transaction in that thread.
 *   Together: non-blocking audit writes that always commit.
 *
 * On ObjectMapper failure (metadata serialization):
 *   Log the error and store null metadata rather than failing the audit write.
 *   An audit entry without metadata is better than no audit entry at all.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class AuditService {

	private final UserAuditLogRepository auditLogRepository;
	private final ObjectMapper           objectMapper;

	/**
	 * Records a single audit event asynchronously.
	 *
	 * @param userId    the user this action applies to
	 * @param action    the type of action (from AuditAction enum)
	 * @param metadata  map of contextual key-value pairs (nullable)
	 * @param ipAddress originating request IP (nullable)
	 */
	@Async
	@Transactional(propagation = Propagation.REQUIRES_NEW)
	public void record(String userId, AuditAction action,
			Map<String, Object> metadata, String ipAddress) {
		String metadataJson = null;
		if (metadata != null && !metadata.isEmpty()) {
			try {
				metadataJson = objectMapper.writeValueAsString(metadata);
			} catch (JsonProcessingException e) {
				log.warn("Failed to serialize audit metadata for action={}: {}", action, e.getMessage());
				// Proceed without metadata rather than failing the audit entry
			}
		}

		UserAuditLog entry = UserAuditLog.builder()
				.userId(userId)
				.action(action)
				.metadata(metadataJson)
				.ipAddress(ipAddress)
				.build();

		try {
			auditLogRepository.save(entry);
		} catch (Exception e) {
			// Never let audit failure propagate upward — it's a side effect, not core logic
			log.error("AUDIT WRITE FAILED for userId={} action={}: {}", userId, action, e.getMessage());
		}
	}

	/** Convenience overload for actions with no metadata */
	@Async
	@Transactional(propagation = Propagation.REQUIRES_NEW)
	public void record(String userId, AuditAction action, String ipAddress) {
		record(userId, action, null, ipAddress);
	}
}
