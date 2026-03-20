package com.deezyWallet.auth_service.user.event.outbound;

import java.time.LocalDateTime;

import com.deezyWallet.auth_service.user.enums.UserEventType;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * Published when a user completes phone OTP verification → status becomes ACTIVE.
 *
 * Consumed by:
 *   - Wallet Service → activates the wallet (INACTIVE → ACTIVE)
 *
 * WHY a separate event instead of embedding verification in REGISTERED?
 *   Registration and verification are separate steps with a time gap between them.
 *   Wallet Service must not activate a wallet until the phone is verified —
 *   an unverified user could have a typo in their phone number or be an
 *   incomplete registration. A separate event makes the activation trigger explicit.
 */
@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserVerifiedEvent {

	private String        eventId;
	private UserEventType eventType;  // always USER_VERIFIED
	private String        userId;
	private String        email;
	private LocalDateTime occurredAt;
}
