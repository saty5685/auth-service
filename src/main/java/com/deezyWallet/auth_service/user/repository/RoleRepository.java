package com.deezyWallet.auth_service.user.repository;

import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.deezyWallet.auth_service.user.entity.Role;

/**
 * Role repository — roles are read-only reference data after seeding.
 *
 * findByName is called during:
 *   - Registration: to assign ROLE_USER to the new user
 *   - Admin operations: to assign ROLE_ADMIN
 *
 * WHY cache roles?
 *   Roles are queried on every registration but never change at runtime.
 *   @Cacheable (Spring Cache + Redis) would eliminate DB round-trips after
 *   first load. For now, simple JPA is sufficient — add caching only if
 *   registration rate is high enough to show up in profiling.
 */
@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {

	Optional<Role> findByName(String name);

	/**
	 * Fetch multiple roles in one query — used when assigning multiple roles.
	 * More efficient than N individual findByName() calls.
	 */
	List<Role> findByNameIn(Set<String> names);
}
