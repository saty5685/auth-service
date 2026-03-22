package com.deezyWallet.auth_service.user.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.deezyWallet.auth_service.user.constants.UserConstants;
import com.deezyWallet.auth_service.user.dto.request.ChangePasswordRequest;
import com.deezyWallet.auth_service.user.dto.request.MfaConfirmRequest;
import com.deezyWallet.auth_service.user.dto.request.UpdateProfileRequest;
import com.deezyWallet.auth_service.user.dto.response.MfaSetupResponse;
import com.deezyWallet.auth_service.user.dto.response.UserProfileResponse;
import com.deezyWallet.auth_service.user.security.JwtService;
import com.deezyWallet.auth_service.user.security.UserPrincipal;
import com.deezyWallet.auth_service.user.service.TokenBlacklistService;
import com.deezyWallet.auth_service.user.service.UserService;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * UserController — self-service profile and security endpoints.
 *
 * BASE PATH: /api/v1/users
 * AUTH:      All endpoints require a valid JWT (authenticated user).
 *            All use the /me pattern — walletId derived from JWT principal.
 *            Zero IDOR risk — users can only access their own data.
 *
 * /me PATTERN:
 *   Every endpoint derives the userId from @AuthenticationPrincipal.
 *   The client never submits a userId — it's always extracted from the
 *   validated JWT. This eliminates the entire class of IDOR vulnerabilities
 *   where a user submits another user's ID.
 *
 * ENDPOINT INVENTORY:
 *   GET  /me              — get own profile
 *   PUT  /me              — update name fields
 *   PUT  /me/password     — change password (requires current)
 *   POST /me/mfa/init     — start MFA setup, get QR URI
 *   POST /me/mfa/confirm  — confirm setup with first TOTP code
 *   DELETE /me/mfa        — disable MFA (requires valid TOTP code)
 */
@RestController
@RequestMapping(UserConstants.API_USER_BASE)
@RequiredArgsConstructor
@Slf4j
public class UserController {

	private final UserService           userService;
	private final JwtService            jwtService;
	private final TokenBlacklistService blacklistService;

	// ── GET /api/v1/users/me ──────────────────────────────────────────────────

	@GetMapping("/me")
	public ResponseEntity<UserProfileResponse> getProfile(
			@AuthenticationPrincipal UserPrincipal principal) {

		return ResponseEntity.ok(userService.getProfile(principal.getUserId()));
	}

	// ── PUT /api/v1/users/me ──────────────────────────────────────────────────

	@PutMapping("/me")
	public ResponseEntity<UserProfileResponse> updateProfile(
			@AuthenticationPrincipal UserPrincipal principal,
			@Valid @RequestBody UpdateProfileRequest req,
			HttpServletRequest httpRequest) {

		return ResponseEntity.ok(
				userService.updateProfile(principal.getUserId(), req, extractIp(httpRequest)));
	}

	// ── PUT /api/v1/users/me/password ─────────────────────────────────────────

	/**
	 * Changes the user's password.
	 *
	 * Post-change: all refresh tokens revoked, all sessions terminated.
	 * The current access token is also blacklisted here (controller concern —
	 * the service doesn't have access to the current request's token).
	 *
	 * Returns 204 No Content — the client must log in again with the new password.
	 * Returning 200 with new tokens would mean the old compromised session
	 * continues seamlessly. Forcing re-login after password change is intentional.
	 */
	@PutMapping("/me/password")
	public ResponseEntity<Void> changePassword(
			@AuthenticationPrincipal UserPrincipal principal,
			@Valid @RequestBody ChangePasswordRequest req,
			@RequestHeader(value = "Authorization", required = false) String authHeader,
			HttpServletRequest httpRequest) {

		userService.changePassword(principal.getUserId(), req, extractIp(httpRequest));

		// Blacklist the current access token — the user must log in again
		// The service already revoked all refresh tokens
		if (authHeader != null && authHeader.startsWith("Bearer ")) {
			String accessToken = authHeader.substring(7);
			try {
				Claims claims = jwtService.validateAndExtract(accessToken);
				long   ttl    = jwtService.getRemainingTtlSeconds(claims);
				blacklistService.blacklist(claims.getId(), ttl);
			} catch (JwtException e) {
				// Already invalid — nothing to blacklist
			}
		}

		return ResponseEntity.noContent().build();
	}

	// ── POST /api/v1/users/me/mfa/init ────────────────────────────────────────

	/**
	 * Initiates MFA setup.
	 *
	 * Returns a QR URI (otpauth://) and a manual entry key.
	 * The user scans the QR in their authenticator app, then must confirm
	 * setup by calling /me/mfa/confirm with their first TOTP code.
	 *
	 * MFA is NOT active until /confirm succeeds.
	 */
	@PostMapping("/me/mfa/init")
	public ResponseEntity<MfaSetupResponse> initMfaSetup(
			@AuthenticationPrincipal UserPrincipal principal) {

		return ResponseEntity.ok(userService.initMfaSetup(principal.getUserId()));
	}

	// ── POST /api/v1/users/me/mfa/confirm ─────────────────────────────────────

	/**
	 * Confirms MFA setup by verifying the first TOTP code from the user's device.
	 *
	 * On success: mfaEnabled = true on the user account.
	 * All subsequent logins will require a TOTP code after the password.
	 */
	@PostMapping("/me/mfa/confirm")
	public ResponseEntity<Void> confirmMfaSetup(
			@AuthenticationPrincipal UserPrincipal principal,
			@Valid @RequestBody MfaConfirmRequest req,
			HttpServletRequest httpRequest) {

		userService.confirmMfaSetup(principal.getUserId(), req, extractIp(httpRequest));
		return ResponseEntity.noContent().build();
	}

	// ── DELETE /api/v1/users/me/mfa ───────────────────────────────────────────

	/**
	 * Disables MFA on the account.
	 *
	 * Requires a valid TOTP code — the user must prove they still have access
	 * to their authenticator app. Prevents someone who stole a session token
	 * from disabling MFA without the physical device.
	 *
	 * WHY DELETE verb?
	 *   Disabling MFA removes a resource (the MFA configuration).
	 *   DELETE is semantically correct. Some teams use POST /me/mfa/disable —
	 *   both are acceptable; DELETE is more RESTful.
	 *
	 * The TOTP code is sent in the request body even for DELETE.
	 * RFC 7231 does not prohibit a body on DELETE — it's uncommon but valid.
	 */
	@DeleteMapping("/me/mfa")
	public ResponseEntity<Void> disableMfa(
			@AuthenticationPrincipal UserPrincipal principal,
			@Valid @RequestBody MfaConfirmRequest req,
			HttpServletRequest httpRequest) {

		userService.disableMfa(principal.getUserId(), req, extractIp(httpRequest));
		return ResponseEntity.noContent().build();
	}

	// ── Private helpers ───────────────────────────────────────────────────────

	private String extractIp(HttpServletRequest request) {
		String xff = request.getHeader("X-Forwarded-For");
		if (xff != null && !xff.isBlank()) {
			return xff.split(",")[0].trim();
		}
		return request.getRemoteAddr();
	}
}
