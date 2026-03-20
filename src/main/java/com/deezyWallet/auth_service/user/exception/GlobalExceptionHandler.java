package com.deezyWallet.auth_service.user.exception;

import java.util.List;

import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import com.deezyWallet.auth_service.user.constants.UserErrorCode;
import com.deezyWallet.auth_service.user.dto.response.ErrorResponse;

import lombok.extern.slf4j.Slf4j;

/**
 * Centralised exception-to-HTTP-response mapping.
 *
 * HANDLER HIERARCHY:
 * ─────────────────────────────────────────────────────────────────────
 *  Most specific                               Most general
 *  ─────────                                   ────────────
 *  UserBaseException subclasses                Exception (catch-all)
 *    AuthException → 401
 *    UserAlreadyExistsException → 409
 *    UserNotFoundException → 404
 *    AccountLockedException → 423
 *    AccountStatusException → 403
 *    InvalidOtpException → 400
 *    OtpMaxAttemptsException → 429
 *    TokenException → 401
 *    MfaException → 400
 *  UserBaseException (parent, catchall) → uses exception.httpStatus
 *  MethodArgumentNotValidException → 400 with field errors
 *  DataIntegrityViolationException → 409 (unique constraint)
 *  AccessDeniedException → 403 (Spring Security)
 *  Exception → 500 (no internal detail in response)
 * ─────────────────────────────────────────────────────────────────────
 *
 * WHY a single UserBaseException handler instead of one per subclass?
 *   Each subclass carries its own httpStatus. The parent handler reads
 *   exception.getHttpStatus() dynamically — adding a new exception class
 *   requires no new handler, just setting the right status in the constructor.
 *   Specific subclass handlers (AuthException, etc.) still exist when
 *   we need logging behaviour that differs by type.
 *
 * SECURITY RULE — AuthException handler:
 *   ALWAYS returns the same generic message regardless of the errorCode.
 *   Never echoes back the exception's actual message, which may hint at
 *   whether the email exists or the password was close.
 *
 * DataIntegrityViolationException:
 *   Catches DB unique-constraint violations that slip through application-level
 *   duplicate checks (race condition between check and insert).
 *   Returns 409 Conflict — same as UserAlreadyExistsException.
 *   Does NOT return the DB error detail (leaks schema info).
 */
@RestControllerAdvice
@Slf4j
public class GlobalExceptionHandler {

	// ── Auth failures — always generic message ────────────────────────────────

	@ExceptionHandler(AuthException.class)
	public ResponseEntity<ErrorResponse> handleAuth(AuthException ex) {
		// Intentionally discard ex.getMessage() — never reveal auth failure reason
		return ResponseEntity
				.status(HttpStatus.UNAUTHORIZED)
				.body(ErrorResponse.of(UserErrorCode.AUTH_FAILED, "Invalid credentials"));
	}

	@ExceptionHandler(AccountLockedException.class)
	public ResponseEntity<ErrorResponse> handleLocked(AccountLockedException ex) {
		// OK to return lockout message — it doesn't reveal whether the email exists
		return ResponseEntity
				.status(ex.getHttpStatus())
				.body(ErrorResponse.of(ex.getErrorCode(), ex.getMessage()));
	}

	// ── All other domain exceptions — use embedded httpStatus ─────────────────

	@ExceptionHandler(UserBaseException.class)
	public ResponseEntity<ErrorResponse> handleDomain(UserBaseException ex) {
		// Log at WARN for 4xx, ERROR for 5xx (UserBaseException subclasses are all 4xx)
		log.warn("Domain exception: errorCode={} status={} message={}",
				ex.getErrorCode(), ex.getHttpStatus(), ex.getMessage());
		return ResponseEntity
				.status(ex.getHttpStatus())
				.body(ErrorResponse.of(ex.getErrorCode(), ex.getMessage()));
	}

	// ── Bean Validation failures (@Valid on request bodies) ──────────────────

	@ExceptionHandler(MethodArgumentNotValidException.class)
	public ResponseEntity<ErrorResponse> handleValidation(MethodArgumentNotValidException ex) {
		List<ErrorResponse.FieldError> fieldErrors = ex.getBindingResult()
				.getFieldErrors()
				.stream()
				.map(fe -> new ErrorResponse.FieldError(
						fe.getField(),
						fe.getDefaultMessage()))
				.toList();

		return ResponseEntity
				.status(HttpStatus.BAD_REQUEST)
				.body(ErrorResponse.ofValidation(UserErrorCode.VALIDATION_FAILED, fieldErrors));
	}

	// ── DB unique constraint race condition ───────────────────────────────────

	@ExceptionHandler(DataIntegrityViolationException.class)
	public ResponseEntity<ErrorResponse> handleDataIntegrity(DataIntegrityViolationException ex) {
		log.warn("Data integrity violation (likely duplicate): {}", ex.getMostSpecificCause().getMessage());
		// Do NOT return ex.getMessage() — it contains table/column names (schema leak)
		return ResponseEntity
				.status(HttpStatus.CONFLICT)
				.body(ErrorResponse.of(UserErrorCode.EMAIL_ALREADY_EXISTS,
						"A user with these credentials already exists"));
	}

	// ── Spring Security access denied (role check failed) ────────────────────

	@ExceptionHandler(AccessDeniedException.class)
	public ResponseEntity<ErrorResponse> handleAccessDenied(AccessDeniedException ex) {
		return ResponseEntity
				.status(HttpStatus.FORBIDDEN)
				.body(ErrorResponse.of(UserErrorCode.ACCESS_DENIED, "Insufficient permissions"));
	}

	// ── Catch-all — never leak internal detail ────────────────────────────────

	@ExceptionHandler(Exception.class)
	public ResponseEntity<ErrorResponse> handleUnexpected(Exception ex) {
		// Log full stack trace internally — return nothing useful externally
		log.error("Unhandled exception: {}", ex.getMessage(), ex);
		return ResponseEntity
				.status(HttpStatus.INTERNAL_SERVER_ERROR)
				.body(ErrorResponse.of(UserErrorCode.INTERNAL_ERROR,
						"An unexpected error occurred. Please try again."));
	}
}
