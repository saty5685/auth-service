package com.deezyWallet.auth_service.user.event.outbound;

import java.time.LocalDateTime;

import com.deezyWallet.auth_service.user.enums.UserEventType;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * Published when a suspended user is reinstated by an admin.
 *
 * Consumed by:
 *   - Wallet Service → unfreezes the wallet (FROZEN → ACTIVE)
 */
@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserReinstatedEvent {

	private String        eventId;
	private UserEventType eventType;  // always USER_REINSTATED
	private String        userId;
	private String        reinstatedByAdminId;
	private LocalDateTime occurredAt;
}

