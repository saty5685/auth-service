package com.deezyWallet.auth_service.config;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import com.deezyWallet.auth_service.utils.JwtUtil;

import io.jsonwebtoken.Claims;
import reactor.core.publisher.Mono;

@Component
public class JwtAuthenticationManager implements ReactiveAuthenticationManager {

	@Autowired
	private JwtUtil jwtUtils;

	@Override
	public Mono<Authentication> authenticate(Authentication authentication) {
		String authToken = authentication.getCredentials().toString();

		try {
			String username = jwtUtils.extractUsername(authToken);
			if (username != null && jwtUtils.validateToken(authToken, username)) {
				Claims claims = jwtUtils.getClaims(authToken);
				// Extract roles/authorities if you have them in the JWT
				List<SimpleGrantedAuthority> authorities = new ArrayList<>();

				return Mono.just(new UsernamePasswordAuthenticationToken(
						username,
						null,
						authorities
				));
			}
		} catch (Exception e) {
			return Mono.empty(); // Authentication failed
		}
		return Mono.empty();
	}

}