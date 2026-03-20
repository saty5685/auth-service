package com.deezyWallet.auth_service.user.event.outbound;

import java.time.LocalDateTime;

import com.deezyWallet.auth_service.user.enums.UserEventType;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * Published to user.events when a new user registers.
 *
 * Consumed by:
 *   - Wallet Service   → auto-provisions a wallet (status INACTIVE)
 *   - Notification Service → sends welcome email + OTP SMS
 *   - KYC Service      → initiates KYC onboarding workflow
 *
 * WHY include otpCode in the event?
 *   The OTP is generated in AuthService and must reach the user via SMS.
 *   SMS delivery is the Notification Service's responsibility.
 *   Passing the OTP in the event avoids a synchronous HTTP call from
 *   User Service → Notification Service during the hot registration path.
 *
 * SECURITY NOTE: This event travels over an internal Kafka topic.
 *   In production, the Kafka broker must use TLS + authentication.
 *   The OTP is short-lived (10 min TTL in Redis) and single-use.
 *   If the event is replayed (Kafka retry), the Notification Service
 *   should be idempotent — checking Redis for the same OTP before re-sending.
 *
 * Immutable: @Getter only, no @Setter, no @Data.
 * Events should never be mutated after construction.
 */
@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserRegisteredEvent {

	/** Unique event ID — for idempotency on consumer side */
	private String         eventId;
	private UserEventType  eventType;  // always USER_REGISTERED

	// User fields needed by consumers
	private String         userId;
	private String         email;
	private String         phoneNumber;
	private String         firstName;
	private String         lastName;

	/** The OTP code — for Notification Service to deliver via SMS */
	private String         otpCode;

	private LocalDateTime  occurredAt;
}
