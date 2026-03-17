package com.deezyWallet.auth_service.user.security;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.Map;

import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import com.deezyWallet.auth_service.user.constants.UserErrorCode;
import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

/**
 * Returns a consistent JSON 403 response for authenticated-but-unauthorized requests.
 *
 * Distinction from CustomAuthEntryPoint:
 *   401 (AuthEntryPoint) — not authenticated (no valid token)
 *   403 (AccessDeniedHandler) — authenticated but insufficient role
 *
 * Both return structured JSON to match the rest of the API error contract.
 */
@Component
@RequiredArgsConstructor
public class CustomAccessDeniedHandler implements AccessDeniedHandler {

	private final ObjectMapper objectMapper;

	@Override
	public void handle(HttpServletRequest  request,
			HttpServletResponse response,
			AccessDeniedException accessDeniedException) throws IOException {
		response.setStatus(HttpServletResponse.SC_FORBIDDEN);
		response.setContentType(MediaType.APPLICATION_JSON_VALUE);
		objectMapper.writeValue(response.getOutputStream(), Map.of(
				"errorCode",  UserErrorCode.ACCESS_DENIED,
				"message",    "Insufficient permissions",
				"timestamp",  LocalDateTime.now().toString()
		));
	}
}
