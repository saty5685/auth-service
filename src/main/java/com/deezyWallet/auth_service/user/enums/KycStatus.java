package com.deezyWallet.auth_service.user.enums;

/**
 * KYC (Know Your Customer) verification status.
 *
 * Managed primarily by the KYC/AML microservice, mirrored here as a
 * denormalized field on the User entity for fast read access.
 *
 * State machine:
 *   UNVERIFIED ──submitDocs──→ PENDING ──approve──→ VERIFIED
 *                                           │
 *                                        ──reject──→ REJECTED ──resubmit──→ PENDING
 *
 * WHY denormalize KYC status on User?
 *   Every transaction limit check needs KYC status. Making a sync HTTP call
 *   to the KYC service on every transaction would add latency and create a
 *   hard dependency. Instead, the KYC service publishes KYC_STATUS_CHANGED
 *   events that User Service consumes and updates this field.
 *   Eventual consistency is acceptable here — there's a grace period.
 */
public enum KycStatus {
	UNVERIFIED,
	PENDING,
	VERIFIED,
	REJECTED
}

