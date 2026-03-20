package com.deezyWallet.auth_service.user.event.outbound;

import java.time.LocalDateTime;

import com.deezyWallet.auth_service.user.enums.UserEventType;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * Published when a user changes their password.
 *
 * Consumed by:
 *   - Notification Service → sends "your password was changed" security alert
 *
 * WHY publish this? What if the user didn't change it themselves?
 *   If an attacker changed the password, the real user receives an alert
 *   and can contact support. Without this event, a compromised account
 *   silently has its password changed.
 */
@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PasswordChangedEvent {

	private String        eventId;
	private UserEventType eventType;  // always PASSWORD_CHANGED
	private String        userId;
	private String        email;
	private LocalDateTime occurredAt;
}
