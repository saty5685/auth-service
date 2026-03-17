package com.deezyWallet.auth_service.user.security;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import lombok.AllArgsConstructor;
import lombok.Getter;

/**
 * Immutable representation of the authenticated principal extracted from a JWT.
 *
 * WHY implement UserDetails?
 *   Spring Security's @AuthenticationPrincipal injection requires an object
 *   that implements UserDetails. By implementing it, controllers can receive
 *   the principal directly:
 *     public ResponseEntity<?> getProfile(@AuthenticationPrincipal UserPrincipal principal)
 *
 * WHY build from JWT claims instead of loading from DB?
 *   Every API request would require a DB round-trip to load the user.
 *   JWT claims carry all information needed for authorization decisions.
 *   DB is only consulted for operations that need current state (e.g. profile update).
 */
@Getter
@AllArgsConstructor
public class UserPrincipal implements UserDetails {

	private final String       userId;
	private final String       email;
	private final String       phone;
	private final String       kycStatus;
	private final List<String> roles;
	private final String       jti;    // JWT ID — for blacklist check

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return roles.stream()
				.map(SimpleGrantedAuthority::new)
				.collect(Collectors.toList());
	}

	/** Not used — password is managed by User entity, not the principal */
	@Override public String  getPassword()           { return null; }
	@Override public String  getUsername()           { return email; }
	@Override public boolean isAccountNonExpired()   { return true; }
	@Override public boolean isAccountNonLocked()    { return true; }
	@Override public boolean isCredentialsNonExpired(){ return true; }
	@Override public boolean isEnabled()             { return true; }
}

