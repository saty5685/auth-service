package com.deezyWallet.auth_service.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import com.deezyWallet.auth_service.repos.JwtSecurityContextRepository;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

	@Autowired
	private JwtSecurityContextRepository jwtRepository;

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http
				.csrf(csrf -> csrf.disable()) // Typical for Auth-Services using JWT
				.authorizeHttpRequests(auth -> auth
						.requestMatchers("/api/login/**", "/api/register/**").permitAll() // Allow login/signup
						.anyRequest().authenticated()
				);

		return http.build();
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
}