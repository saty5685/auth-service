package com.deezyWallet.auth_service.user.security;

import com.deezyWallet.auth_service.user.constants.UserConstants;
import com.deezyWallet.auth_service.user.service.TokenBlacklistService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

/**
 * JWT authentication filter — runs once per request.
 *
 * Extracts Bearer token → validates → checks blacklist → sets SecurityContext.
 *
 * FILTER BEHAVIOUR:
 *   Missing token → passes through (anonymous) — let SecurityConfig decide
 *   Invalid token → clears context, passes through — SecurityConfig will 401
 *   Blacklisted token → treated same as invalid
 *   Valid token → sets UserPrincipal in SecurityContext
 *
 * WHY OncePerRequestFilter?
 *   Servlet filters can be invoked multiple times in a request if there's
 *   a forward or include. OncePerRequestFilter guarantees exactly one execution
 *   regardless of dispatch type.
 *
 * WHY not throw on missing token?
 *   Public endpoints (/auth/**) have no token. Throwing here would prevent
 *   registration and login. Instead, we let the SecurityConfig's
 *   .authorizeHttpRequests() rules decide what's allowed without a token.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAuthFilter extends OncePerRequestFilter {

	private final JwtService            jwtService;
	private final TokenBlacklistService blacklistService;

	@Override
	protected void doFilterInternal(HttpServletRequest  request,
			HttpServletResponse response,
			FilterChain         chain)
			throws ServletException, IOException {

		String token = extractBearerToken(request);

		if (StringUtils.hasText(token)) {
			try {
				Claims claims = jwtService.validateAndExtract(token);

				// Blacklist check — token was valid at issue but revoked on logout
				String jti = claims.getId();
				if (blacklistService.isBlacklisted(jti)) {
					log.debug("Rejected blacklisted token jti={}", jti);
					// Fall through — SecurityContext stays empty, request will 401
				} else {
					setAuthentication(claims, jti, request);
				}

			} catch (JwtException e) {
				// Expired, tampered, or malformed — log at DEBUG, not WARN
				// A lot of legitimate expired-token 401s would flood WARN logs
				log.debug("JWT validation failed: {}", e.getMessage());
				SecurityContextHolder.clearContext();
			}
		}

		chain.doFilter(request, response);
	}

	@SuppressWarnings("unchecked")
	private void setAuthentication(Claims claims, String jti, HttpServletRequest request) {
		List<String> roles = claims.get(UserConstants.JWT_CLAIM_ROLES, List.class);

		UserPrincipal principal = new UserPrincipal(
				claims.getSubject(),
				claims.get(UserConstants.JWT_CLAIM_EMAIL,      String.class),
				claims.get(UserConstants.JWT_CLAIM_PHONE,      String.class),
				claims.get(UserConstants.JWT_CLAIM_KYC_STATUS, String.class),
				roles != null ? roles : List.of(),
				jti
		);

		UsernamePasswordAuthenticationToken authentication =
				new UsernamePasswordAuthenticationToken(principal, null, principal.getAuthorities());
		authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
		SecurityContextHolder.getContext().setAuthentication(authentication);
	}

	private String extractBearerToken(HttpServletRequest request) {
		String header = request.getHeader("Authorization");
		if (StringUtils.hasText(header) && header.startsWith("Bearer ")) {
			return header.substring(7);
		}
		return null;
	}
}
