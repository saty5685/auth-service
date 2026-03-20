package com.deezyWallet.auth_service.user.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Response for the token refresh endpoint.
 * Always issues a new pair — refresh token rotation.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TokenRefreshResponse {

	private String accessToken;
	private String refreshToken;
}
