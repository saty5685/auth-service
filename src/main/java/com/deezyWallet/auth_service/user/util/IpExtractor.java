package com.deezyWallet.auth_service.user.util;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Utility for extracting the real client IP from an HTTP request.
 *
 * All three controllers duplicate this logic. Extracted here to a shared
 * utility to eliminate that duplication.
 *
 * WHY a static utility instead of a Spring @Component?
 *   IP extraction is pure logic with no dependencies — no need for a Spring
 *   bean lifecycle. Static utility is simpler and easier to test in isolation.
 *
 * HEADER PRIORITY:
 *   1. X-Forwarded-For  — set by API Gateway / reverse proxy (Nginx, AWS ALB)
 *                         May be comma-separated if through multiple proxies:
 *                         "203.0.113.1, 10.0.0.1" — take the first (original client)
 *   2. X-Real-IP        — set by some reverse proxy configurations (Nginx real_ip module)
 *   3. getRemoteAddr()  — direct TCP connection IP (always available, may be proxy IP)
 *
 * SECURITY NOTE:
 *   X-Forwarded-For CAN be spoofed by the client unless the API Gateway strips
 *   and re-sets it. Used here only for audit logging — not for security decisions.
 *   For rate limiting or IP-based access control, use a trusted header that
 *   the Gateway explicitly sets, or use getRemoteAddr() at the gateway edge.
 */
public final class IpExtractor {

	private IpExtractor() {}

	public static String extract(HttpServletRequest request) {
		String xff = request.getHeader("X-Forwarded-For");
		if (xff != null && !xff.isBlank()) {
			return xff.split(",")[0].trim();
		}
		String xRealIp = request.getHeader("X-Real-IP");
		if (xRealIp != null && !xRealIp.isBlank()) {
			return xRealIp.trim();
		}
		return request.getRemoteAddr();
	}
}
