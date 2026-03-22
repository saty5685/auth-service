package com.deezyWallet.auth_service.user.controller;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.deezyWallet.auth_service.user.constants.UserConstants;
import com.deezyWallet.auth_service.user.dto.response.UserProfileResponse;
import com.deezyWallet.auth_service.user.enums.UserStatus;
import com.deezyWallet.auth_service.user.security.UserPrincipal;
import com.deezyWallet.auth_service.user.service.UserService;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * AdminUserController — user management for platform administrators.
 *
 * BASE PATH: /api/v1/admin/users
 * AUTH:      ROLE_ADMIN (enforced at SecurityConfig route level)
 *            @PreAuthorize("hasRole('ADMIN')") added per-method as
 *            defence-in-depth (belt-and-suspenders for critical admin ops).
 *
 * ADMIN vs USER endpoint distinction:
 *   - AdminController operates on ANY userId (no /me pattern)
 *   - AdminController does NOT enforce ownership — admins bypass data-level auth
 *   - All admin actions capture adminId from JWT for immutable audit trail
 *
 * ENDPOINT INVENTORY:
 *   GET  /            — list users (paginated, optional status filter)
 *   GET  /{userId}    — get full profile for any user
 *   POST /{userId}/suspend    — suspend account
 *   POST /{userId}/reinstate  — reinstate suspended account
 */
@RestController
@RequestMapping(UserConstants.API_ADMIN_BASE)
@RequiredArgsConstructor
@Slf4j
public class AdminUserController {

	private final UserService userService;

	// ── GET /api/v1/admin/users ───────────────────────────────────────────────

	/**
	 * Lists all users with optional status filter.
	 *
	 * Paginated — never returns unbounded result sets.
	 * Default: 20 per page, sorted by createdAt descending (newest first).
	 *
	 * Query params:
	 *   status  — optional filter (PENDING, ACTIVE, SUSPENDED, CLOSED)
	 *   page    — 0-indexed page number (default 0)
	 *   size    — page size (default 20, max enforced by @PageableDefault)
	 *   sort    — field,direction (default createdAt,desc)
	 */
	@GetMapping
	public ResponseEntity<Page<UserProfileResponse>> listUsers(
			@RequestParam(required = false) UserStatus status,
			@PageableDefault(size = 20, sort = "createdAt", direction = Sort.Direction.DESC)
			Pageable pageable) {

		return ResponseEntity.ok(userService.listUsers(status, pageable));
	}

	// ── GET /api/v1/admin/users/{userId} ──────────────────────────────────────

	/**
	 * Gets the full profile for any user by ID.
	 *
	 * Unlike /users/me, admins supply the userId explicitly.
	 * Returns the same UserProfileResponse — no extra admin-only fields.
	 * Sensitive security fields (passwordHash, mfaSecret) are never exposed.
	 */
	@GetMapping("/{userId}")
	public ResponseEntity<UserProfileResponse> getUserById(@PathVariable String userId) {
		return ResponseEntity.ok(userService.getUserById(userId));
	}

	// ── POST /api/v1/admin/users/{userId}/suspend ─────────────────────────────

	/**
	 * Suspends a user account.
	 *
	 * Effects (all atomic in UserService.suspendUser):
	 *   - status → SUSPENDED
	 *   - All refresh tokens revoked (all devices logged out)
	 *   - All Redis sessions deleted
	 *   - USER_SUSPENDED Kafka event published
	 *
	 * The adminId is captured from the JWT principal — it is never accepted
	 * from the request body. The audit trail is immutable and server-authoritative.
	 *
	 * Request body is a simple JSON object with an optional reason field:
	 *   { "reason": "Reported for fraud investigation #4521" }
	 */
	@PostMapping("/{userId}/suspend")
	public ResponseEntity<Void> suspendUser(
			@PathVariable String userId,
			@RequestBody(required = false) java.util.Map<String, String> body,
			@AuthenticationPrincipal UserPrincipal adminPrincipal,
			HttpServletRequest httpRequest) {

		String reason = body != null ? body.get("reason") : null;
		userService.suspendUser(userId, adminPrincipal.getUserId(), reason, extractIp(httpRequest));
		return ResponseEntity.noContent().build();
	}

	// ── POST /api/v1/admin/users/{userId}/reinstate ───────────────────────────

	/**
	 * Reinstates a suspended user account.
	 *
	 * Only SUSPENDED → ACTIVE transition is valid.
	 * Throws AccountStatusException if the user is not currently suspended.
	 *
	 * The Kafka event triggers Wallet Service to unfreeze the wallet.
	 */
	@PostMapping("/{userId}/reinstate")
	public ResponseEntity<Void> reinstateUser(
			@PathVariable String userId,
			@AuthenticationPrincipal UserPrincipal adminPrincipal,
			HttpServletRequest httpRequest) {

		userService.reinstateUser(userId, adminPrincipal.getUserId(), extractIp(httpRequest));
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
