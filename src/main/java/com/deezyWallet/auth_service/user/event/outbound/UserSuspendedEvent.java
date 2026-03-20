package com.deezyWallet.auth_service.user.event.outbound;

import java.time.LocalDateTime;

import com.deezyWallet.auth_service.user.enums.UserEventType;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * Published when an admin suspends a user account.
 *
 * Consumed by:
 *   - Wallet Service     → freezes the user's wallet (blocks all transactions)
 *   - Notification Service → sends suspension alert to user
 *
 * Includes the suspending admin's ID for audit trail traceability.
 */
@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserSuspendedEvent {

	private String        eventId;
	private UserEventType eventType;  // always USER_SUSPENDED
	private String        userId;
	private String        suspendedByAdminId;
	private String        reason;
	private LocalDateTime occurredAt;
}

