package com.deezyWallet.auth_service.user.event;

import java.time.LocalDateTime;
import java.util.UUID;

import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Component;

import com.deezyWallet.auth_service.user.constants.UserConstants;
import com.deezyWallet.auth_service.user.entity.User;
import com.deezyWallet.auth_service.user.enums.UserEventType;
import com.deezyWallet.auth_service.user.event.outbound.PasswordChangedEvent;
import com.deezyWallet.auth_service.user.event.outbound.UserRegisteredEvent;
import com.deezyWallet.auth_service.user.event.outbound.UserReinstatedEvent;
import com.deezyWallet.auth_service.user.event.outbound.UserSuspendedEvent;
import com.deezyWallet.auth_service.user.event.outbound.UserVerifiedEvent;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Centralised Kafka event publisher for all User Service outbound events.
 *
 * All events go to the same topic (user.events), keyed by userId.
 * Keying by userId ensures all events for the same user land on the same
 * partition → consumers see per-user events in order.
 *
 * FIRE-AND-FORGET pattern:
 *   publish() is non-blocking — the KafkaTemplate sends asynchronously.
 *   Delivery failures are logged but never thrown back to callers.
 *
 *   WHY not block for ACK?
 *     The publish call happens inside @Transactional service methods.
 *     Blocking for Kafka ACK would hold the DB transaction open during
 *     broker I/O — a connection-pool exhaustion risk under load.
 *     The DB transaction commits independently of Kafka delivery.
 *
 * OUTBOX PATTERN (future hardening):
 *   Fire-and-forget means events can be lost on broker unavailability.
 *   Production hardening: write events to a DB outbox table inside the
 *   same transaction, then have a separate poller publish them to Kafka.
 *   This guarantees exactly-once delivery even on broker restarts.
 *   For now, fire-and-forget is acceptable — Kafka's high availability
 *   makes loss extremely rare in practice.
 *
 * All publish methods never throw — failures are logged with full context
 * for manual replay if needed.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class UserEventPublisher {

	private final KafkaTemplate<String, Object> kafkaTemplate;

	public void publishUserRegistered(User user, String otpCode) {
		UserRegisteredEvent event = UserRegisteredEvent.builder()
				.eventId(UUID.randomUUID().toString())
				.eventType(UserEventType.USER_REGISTERED)
				.userId(user.getId())
				.email(user.getEmail())
				.phoneNumber(user.getPhoneNumber())
				.firstName(user.getFirstName())
				.lastName(user.getLastName())
				.otpCode(otpCode)
				.occurredAt(LocalDateTime.now())
				.build();
		publish(user.getId(), event, UserEventType.USER_REGISTERED);
	}

	public void publishUserVerified(User user) {
		UserVerifiedEvent event = UserVerifiedEvent.builder()
				.eventId(UUID.randomUUID().toString())
				.eventType(UserEventType.USER_VERIFIED)
				.userId(user.getId())
				.email(user.getEmail())
				.occurredAt(LocalDateTime.now())
				.build();
		publish(user.getId(), event, UserEventType.USER_VERIFIED);
	}

	public void publishUserSuspended(User user) {
		UserSuspendedEvent event = UserSuspendedEvent.builder()
				.eventId(UUID.randomUUID().toString())
				.eventType(UserEventType.USER_SUSPENDED)
				.userId(user.getId())
				.occurredAt(LocalDateTime.now())
				.build();
		publish(user.getId(), event, UserEventType.USER_SUSPENDED);
	}

	public void publishUserSuspended(User user, String adminId, String reason) {
		UserSuspendedEvent event = UserSuspendedEvent.builder()
				.eventId(UUID.randomUUID().toString())
				.eventType(UserEventType.USER_SUSPENDED)
				.userId(user.getId())
				.suspendedByAdminId(adminId)
				.reason(reason)
				.occurredAt(LocalDateTime.now())
				.build();
		publish(user.getId(), event, UserEventType.USER_SUSPENDED);
	}

	public void publishUserReinstated(User user) {
		UserReinstatedEvent event = UserReinstatedEvent.builder()
				.eventId(UUID.randomUUID().toString())
				.eventType(UserEventType.USER_REINSTATED)
				.userId(user.getId())
				.occurredAt(LocalDateTime.now())
				.build();
		publish(user.getId(), event, UserEventType.USER_REINSTATED);
	}

	public void publishPasswordChanged(User user) {
		PasswordChangedEvent event = PasswordChangedEvent.builder()
				.eventId(UUID.randomUUID().toString())
				.eventType(UserEventType.PASSWORD_CHANGED)
				.userId(user.getId())
				.email(user.getEmail())
				.occurredAt(LocalDateTime.now())
				.build();
		publish(user.getId(), event, UserEventType.PASSWORD_CHANGED);
	}

	// ── Internal publish helper ───────────────────────────────────────────────

	private void publish(String key, Object event, UserEventType type) {
		try {
			kafkaTemplate.send(UserConstants.TOPIC_USER_EVENTS, key, event);
			log.debug("Published {} event for userId={}", type, key);
		} catch (Exception e) {
			// Never propagate — log for manual replay
			log.error("KAFKA PUBLISH FAILED: type={} userId={} error={}",
					type, key, e.getMessage(), e);
		}
	}
}
