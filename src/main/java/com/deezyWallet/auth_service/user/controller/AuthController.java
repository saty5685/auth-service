package com.deezyWallet.auth_service.user.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.deezyWallet.auth_service.user.constants.UserConstants;
import com.deezyWallet.auth_service.user.dto.request.LoginRequest;
import com.deezyWallet.auth_service.user.dto.request.OtpVerifyRequest;
import com.deezyWallet.auth_service.user.dto.request.RegisterRequest;
import com.deezyWallet.auth_service.user.dto.request.TokenRefreshRequest;
import com.deezyWallet.auth_service.user.dto.response.AuthResponse;
import com.deezyWallet.auth_service.user.dto.response.TokenRefreshResponse;
import com.deezyWallet.auth_service.user.security.JwtService;
import com.deezyWallet.auth_service.user.security.UserPrincipal;
import com.deezyWallet.auth_service.user.service.AuthService;
import com.deezyWallet.auth_service.user.service.TokenBlacklistService;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * AuthController — all public authentication endpoints.
 *
 * BASE PATH: /api/v1/auth
 * AUTH:      All endpoints are permitAll in SecurityConfig.
 *            Some (logout) still require a valid JWT for the operation to make
 *            sense, but we don't gate them at the security layer — we validate
 *            the token inside the handler when needed.
 *
 * IP ADDRESS EXTRACTION:
 *   Every auth operation captures the client IP for:
 *   - Audit log (AuditService.record)
 *   - RefreshToken.ipAddress (for admin session review)
 *   - Account lockout events
 *
 *   extractIp() checks X-Forwarded-For first (set by reverse proxy/API gateway),
 *   then falls back to getRemoteAddr(). In production behind an API gateway,
 *   X-Forwarded-For is the real client IP.
 *
 * RESPONSE CODES:
 *   POST /register    → 201 Created    (new resource created)
 *   POST /verify-otp  → 200 OK         (state change, not creation)
 *   POST /login       → 200 OK
 *   POST /login/mfa   → 200 OK
 *   POST /refresh     → 200 OK
 *   POST /logout      → 204 No Content  (success, nothing to return)
 */
@RestController
@RequestMapping(UserConstants.API_AUTH_BASE)
@RequiredArgsConstructor
@Slf4j
public class AuthController {

	private final AuthService           authService;
	private final JwtService            jwtService;
	private final TokenBlacklistService blacklistService;

	// ── POST /api/v1/auth/register ────────────────────────────────────────────

	/**
	 * Registers a new user account.
	 *
	 * Returns 201 with PENDING_OTP status — the client must submit the OTP
	 * received via SMS to /verify-otp before the account is usable.
	 */
	@PostMapping("/register")
	public ResponseEntity<AuthResponse> register(
			@Valid @RequestBody RegisterRequest req,
			HttpServletRequest httpRequest) {

		AuthResponse response = authService.register(req, extractIp(httpRequest));
		return ResponseEntity.status(HttpStatus.CREATED).body(response);
	}

	// ── POST /api/v1/auth/verify-otp ─────────────────────────────────────────

	/**
	 * Verifies the registration OTP and activates the account.
	 *
	 * On success returns a full SUCCESS AuthResponse with access + refresh tokens.
	 * The user is logged in immediately after verification — no second login step.
	 */
	@PostMapping("/verify-otp")
	public ResponseEntity<AuthResponse> verifyOtp(
			@Valid @RequestBody OtpVerifyRequest req,
			HttpServletRequest httpRequest) {

		AuthResponse response = authService.verifyRegistrationOtp(req, extractIp(httpRequest));
		return ResponseEntity.ok(response);
	}

	// ── POST /api/v1/auth/login ───────────────────────────────────────────────

	/**
	 * Authenticates with email + password.
	 *
	 * Returns one of three AuthResponse states:
	 *   SUCCESS      — tokens issued, user logged in
	 *   MFA_REQUIRED — password correct, TOTP code needed (POST to /login/mfa)
	 *   (errors are thrown as exceptions → GlobalExceptionHandler)
	 */
	@PostMapping("/login")
	public ResponseEntity<AuthResponse> login(
			@Valid @RequestBody LoginRequest req,
			HttpServletRequest httpRequest) {

		AuthResponse response = authService.login(req, extractIp(httpRequest));
		return ResponseEntity.ok(response);
	}

	// ── POST /api/v1/auth/login/mfa ───────────────────────────────────────────

	/**
	 * Second step of MFA login — verifies TOTP code.
	 *
	 * Only reachable if /login returned MFA_REQUIRED.
	 * The userId from that response must be submitted here.
	 */
	@PostMapping("/login/mfa")
	public ResponseEntity<AuthResponse> verifyMfa(
			@Valid @RequestBody OtpVerifyRequest req,
			HttpServletRequest httpRequest) {

		AuthResponse response = authService.verifyMfaLogin(req, extractIp(httpRequest));
		return ResponseEntity.ok(response);
	}

	// ── POST /api/v1/auth/refresh ─────────────────────────────────────────────

	/**
	 * Rotates a refresh token — issues a new access + refresh pair.
	 *
	 * The submitted refresh token is revoked and a new one issued.
	 * If the submitted token was already revoked (replay attack), ALL sessions
	 * for the user are terminated — see AuthService.refresh() for details.
	 */
	@PostMapping("/refresh")
	public ResponseEntity<TokenRefreshResponse> refresh(
			@Valid @RequestBody TokenRefreshRequest req,
			HttpServletRequest httpRequest) {

		TokenRefreshResponse response = authService.refresh(req, extractIp(httpRequest));
		return ResponseEntity.ok(response);
	}

	// ── POST /api/v1/auth/logout ──────────────────────────────────────────────

	/**
	 * Logs out the current session.
	 *
	 * Requires the refresh token in the body AND the access token in the
	 * Authorization header. Both are invalidated:
	 *   - Refresh token → revoked in DB
	 *   - Access token  → JTI blacklisted in Redis until natural expiry
	 *
	 * WHY accept logout without mandatory authentication in SecurityConfig?
	 *   If the access token is already expired, the user cannot authenticate
	 *   to call logout. We should still allow them to revoke their refresh token.
	 *   The handler validates what it can — blacklists the access token only
	 *   if it's still valid, and always revokes the refresh token.
	 *
	 * Returns 204 No Content — nothing useful to return after logout.
	 */
	@PostMapping("/logout")
	public ResponseEntity<Void> logout(
			@Valid @RequestBody TokenRefreshRequest req,
			@RequestHeader(value = "Authorization", required = false) String authHeader,
			@AuthenticationPrincipal UserPrincipal principal,
			HttpServletRequest httpRequest) {

		// Extract raw access token from Authorization header if present
		String accessToken = null;
		if (authHeader != null && authHeader.startsWith("Bearer ")) {
			accessToken = authHeader.substring(7);
		}

		// userId from principal if authenticated, else try to extract from access token
		String userId = null;
		if (principal != null) {
			userId = principal.getUserId();
		} else if (accessToken != null) {
			try {
				Claims claims = jwtService.validateAndExtract(accessToken);
				userId = claims.getSubject();
			} catch (JwtException e) {
				// Access token invalid/expired — that's okay, we still revoke refresh token
				log.debug("Logout: access token invalid, will still revoke refresh token");
			}
		}

		authService.logout(req.getRefreshToken(), accessToken, userId, extractIp(httpRequest));
		return ResponseEntity.noContent().build();
	}

	// ── Private helpers ───────────────────────────────────────────────────────

	/**
	 * Extracts the real client IP address.
	 *
	 * Priority:
	 *   1. X-Forwarded-For header (set by API Gateway / reverse proxy)
	 *   2. X-Real-IP header (set by Nginx)
	 *   3. getRemoteAddr() — direct connection IP (loopback in dev)
	 *
	 * In production behind an API Gateway, X-Forwarded-For is the
	 * real client IP. getRemoteAddr() would return the gateway's IP.
	 *
	 * WHY not always use X-Forwarded-For?
	 *   X-Forwarded-For can be spoofed by clients — never trust it for
	 *   security decisions. Here we use it only for audit/logging, where
	 *   best-effort accuracy is acceptable.
	 */
	private String extractIp(HttpServletRequest request) {
		String xff = request.getHeader("X-Forwarded-For");
		if (xff != null && !xff.isBlank()) {
			// May be comma-separated list — first entry is the original client
			return xff.split(",")[0].trim();
		}
		String xRealIp = request.getHeader("X-Real-IP");
		if (xRealIp != null && !xRealIp.isBlank()) {
			return xRealIp.trim();
		}
		return request.getRemoteAddr();
	}
}
