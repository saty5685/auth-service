package com.deezyWallet.auth_service.user.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Returned when a user initiates MFA setup.
 *
 * The client must:
 *   1. Display the QR code (from qrCodeUrl) to the user for scanning.
 *   2. Or show the manualEntryKey for manual entry in the authenticator app.
 *   3. Prompt the user for the first TOTP code to confirm setup.
 *   4. POST the code to /me/mfa/confirm to activate MFA.
 *
 * Until /me/mfa/confirm succeeds, mfaEnabled remains false on the User.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class MfaSetupResponse {

	/** otpauth:// URI — can be encoded as QR by the client */
	private String otpauthUrl;

	/** Base32-encoded TOTP secret — for manual entry in authenticator apps */
	private String manualEntryKey;
}
