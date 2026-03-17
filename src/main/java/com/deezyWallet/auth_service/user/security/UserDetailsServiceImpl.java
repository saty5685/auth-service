package com.deezyWallet.auth_service.user.security;

import com.deezyWallet.auth_service.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Loads user details by email from DB for Spring Security's auth manager.
 *
 * WHY do we need this if JwtAuthFilter handles JWT-based auth?
 *   JwtAuthFilter handles stateless JWT auth — no DB call needed.
 *   UserDetailsService is used by Spring's DaoAuthenticationProvider,
 *   which is only invoked during the initial username/password login.
 *   AuthService.login() calls authenticationManager.authenticate(), which
 *   internally calls loadUserByUsername() to verify credentials.
 *
 * This is the bridge between Spring Security's auth machinery and our User entity.
 */
@Service
@RequiredArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {

	private final UserRepository userRepository;

	@Override
	@Transactional(readOnly = true)
	public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
		return userRepository.findByEmail(email)
				.map(user -> org.springframework.security.core.userdetails.User.builder()
						.username(user.getEmail())
						.password(user.getPasswordHash())
						.authorities(user.getRoles().stream()
								.map(r -> new org.springframework.security.core.authority.SimpleGrantedAuthority(r.getName()))
								.toList())
						.build())
				.orElseThrow(() -> new UsernameNotFoundException("User not found: " + email));
	}
}
