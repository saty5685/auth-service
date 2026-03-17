package com.deezyWallet.auth_service.user.entity;

import jakarta.persistence.*;
import lombok.*;

/**
 * System role entity — seeded at startup, never created at runtime.
 *
 * Roles are immutable reference data. The application never creates or
 * deletes roles via API — only reads and assigns them to users.
 *
 * WHY Long ID instead of UUID?
 *   Roles are a tiny, stable lookup table (4-5 rows ever).
 *   Long PKs are smaller and faster to join on than UUIDs.
 *   Security-through-obscurity is not a concern here — role IDs
 *   are never exposed to clients. Users see role names in JWT claims.
 *
 * Stored role names must match UserConstants.ROLE_* exactly.
 * These values appear in JWT claims and in @PreAuthorize expressions.
 */
@Entity
@Table(name = "roles")
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@EqualsAndHashCode(of = "name")  // Identity by name, not DB PK
public class Role {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	@Column(nullable = false, unique = true, length = 50)
	private String name;  // e.g. "ROLE_USER", "ROLE_ADMIN"
}
