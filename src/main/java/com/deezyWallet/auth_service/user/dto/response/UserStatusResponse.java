package com.deezyWallet.auth_service.user.dto.response;

import com.deezyWallet.auth_service.user.enums.KycStatus;
import com.deezyWallet.auth_service.user.enums.UserStatus;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Minimal response for internal service calls (Wallet, Transaction Service).
 *
 * WHY not return the full UserProfileResponse?
 *   Internal services only need to know: can this user transact?
 *   They don't need name, email, or login history.
 *   Principle of least information — return only what the consumer needs.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserStatusResponse {

	private String     userId;
	private UserStatus status;
	private KycStatus  kycStatus;
	private boolean    canTransact;   // computed: status == ACTIVE
	private boolean    loginLocked;   // computed: failedLoginAttempts >= threshold
}