package com.deezyWallet.auth_service.user.security;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.Map;

import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import com.deezyWallet.auth_service.user.constants.UserErrorCode;
import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

/**
 * Returns a consistent JSON 401 response for unauthenticated requests.
 *
 * WHY a custom entry point instead of the default Spring behaviour?
 *   Spring's default returns an HTML 401 page (white label error).
 *   REST API clients expect JSON. A custom entry point ensures all 401s
 *   have the same structure as our other error responses.
 */
@Component
@RequiredArgsConstructor
public class CustomAuthEntryPoint implements AuthenticationEntryPoint {

	private final ObjectMapper objectMapper;

	@Override
	public void commence(HttpServletRequest  request,
			HttpServletResponse response,
			AuthenticationException authException) throws IOException {
		response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
		response.setContentType(MediaType.APPLICATION_JSON_VALUE);
		objectMapper.writeValue(response.getOutputStream(), Map.of(
				"errorCode",  UserErrorCode.AUTH_FAILED,
				"message",    "Authentication required",
				"timestamp",  LocalDateTime.now().toString()
		));
	}
}
