package com.deezyWallet.auth_service.user.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.deezyWallet.auth_service.user.constants.UserConstants;
import com.deezyWallet.auth_service.user.security.CustomAccessDeniedHandler;
import com.deezyWallet.auth_service.user.security.CustomAuthEntryPoint;
import com.deezyWallet.auth_service.user.security.JwtAuthFilter;
import com.deezyWallet.auth_service.user.security.UserDetailsServiceImpl;

import lombok.RequiredArgsConstructor;

/**
 * Spring Security configuration for User & Identity Service.
 *
 * Route authorization matrix:
 * ─────────────────────────────────────────────────────────────────────
 *  /api/v1/auth/**            → Public (login, register, OTP, refresh)
 *  /actuator/health           → Public (liveness probe)
 *  /api/v1/admin/users/**     → ROLE_ADMIN
 *  /internal/v1/users/**     → ROLE_INTERNAL_SERVICE
 *  /api/v1/users/**           → Any authenticated user
 * ─────────────────────────────────────────────────────────────────────
 *
 * WHY STATELESS session policy?
 *   JWT is stateless — no HttpSession needed.
 *   Disabling session creation reduces memory footprint and prevents
 *   session fixation attacks.
 *
 * WHY BCryptPasswordEncoder(12)?
 *   Cost factor 12 = ~250ms hashing time on modern hardware.
 *   Brute-forcing 1M passwords/second takes ~2778 years per account.
 *   Cost factor 10 (Spring's default) = ~65ms — reasonable but we
 *   accept the extra 185ms per login for significantly better security.
 *
 * @EnableMethodSecurity enables @PreAuthorize on controller methods.
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

	private final JwtAuthFilter           jwtAuthFilter;
	private final UserDetailsServiceImpl  userDetailsService;
	private final CustomAuthEntryPoint    authEntryPoint;
	private final CustomAccessDeniedHandler accessDeniedHandler;

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		return http
				.csrf(csrf -> csrf.disable())
				.sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
				.exceptionHandling(e -> e
						.authenticationEntryPoint(authEntryPoint)
						.accessDeniedHandler(accessDeniedHandler))
				.authorizeHttpRequests(auth -> auth
						// Public endpoints — no token required
						.requestMatchers(UserConstants.API_AUTH_BASE + "/**").permitAll()
						.requestMatchers(UserConstants.ACTUATOR_HEALTH).permitAll()
						// Role-gated endpoints
						.requestMatchers(UserConstants.API_ADMIN_BASE + "/**").hasRole("ADMIN")
						.requestMatchers(UserConstants.API_INTERNAL_BASE + "/**").hasRole("INTERNAL_SERVICE")
						// All other endpoints require authentication
						.anyRequest().authenticated()
				)
				.authenticationProvider(daoAuthenticationProvider())
				.addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
				.build();
	}

	@Bean
	public DaoAuthenticationProvider daoAuthenticationProvider() {
		DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
		provider.setUserDetailsService(userDetailsService);
		provider.setPasswordEncoder(passwordEncoder());
		return provider;
	}

	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration config)
			throws Exception {
		return config.getAuthenticationManager();
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder(12);
	}
}