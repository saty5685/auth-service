package com.deezyWallet.auth_service.user.enums;

/**
 * Kafka event type discriminator for the user.events topic.
 *
 * All outbound Kafka messages from User Service go to the same topic
 * (user.events) and carry one of these types. Consumers filter on this field.
 *
 * WHY a single topic with a type discriminator instead of one topic per event?
 *   N services × M event types = N×M topic subscriptions. Hard to manage.
 *   A single topic with filtering means each consumer subscribes once and
 *   ignores types it doesn't care about. Forward compatible — new event types
 *   added here are ignored by existing consumers unless they explicitly handle them.
 */
public enum UserEventType {
	USER_REGISTERED,    // → Wallet Service (provision), Notification (welcome), KYC (initiate)
	USER_VERIFIED,      // → Wallet Service (activate wallet)
	USER_SUSPENDED,     // → Wallet Service (freeze wallet), Notification (alert)
	USER_REINSTATED,    // → Wallet Service (unfreeze)
	USER_CLOSED,        // → Wallet Service (close wallet)
	PASSWORD_CHANGED,   // → Notification (security alert)
	KYC_STATUS_CHANGED  // internal: KYC service → User Service (consumed, not published)
}