package com.deezyWallet.auth_service.repos;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import com.deezyWallet.auth_service.config.JwtAuthenticationManager;

import reactor.core.publisher.Mono;

@Component
public class JwtSecurityContextRepository implements ServerSecurityContextRepository {
	private final JwtAuthenticationManager authenticationManager;

	public JwtSecurityContextRepository(JwtAuthenticationManager authenticationManager) {
		this.authenticationManager = authenticationManager;
	}

	@Override
	public Mono<Void> save(ServerWebExchange exchange, SecurityContext context) {
		return Mono.empty();
	}

	@Override
	public Mono<SecurityContext> load(ServerWebExchange exchange) {
		return extractToken(exchange)
				.map(token -> new UsernamePasswordAuthenticationToken(null, token))
				.flatMap(authenticationManager::authenticate)
				.map(SecurityContextImpl::new);
	}

	private Mono<String> extractToken(ServerWebExchange exchange) {
		return Mono.justOrEmpty(exchange.getRequest().getHeaders().getFirst("Authorization"))
				.filter(authHeader -> authHeader.startsWith("Bearer "))
				.map(authHeader -> authHeader.substring(7));
	}
}