package com.deezyWallet.auth_service.utils;

import java.security.Key;
import java.util.Date;

import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

@Component
public class JwtUtil {
	private final String SECRET = "your_very_long_and_very_secure_secret_key_here";
	private final Key key = Keys.hmacShaKeyFor(SECRET.getBytes());

	public String generateToken(String username) {

		return Jwts.builder()
				.setSubject(username)
				.setIssuedAt(new Date())
				.setExpiration(
						new Date(System.currentTimeMillis() + 1000 * 60 * 60)
				)
				.signWith(
						Keys.hmacShaKeyFor(SECRET.getBytes()),
						SignatureAlgorithm.HS256
				)
				.compact();
	}

	public String extractUsername(String token) {
		return extractAllClaims(token).getSubject();
	}

	public boolean validateToken(String token,
			String username) {
		return username.equals(username)
				&& !isTokenExpired(token);
	}

	private boolean isTokenExpired(String token) {
		return extractAllClaims(token)
				.getExpiration()
				.before(new Date());
	}

	private Claims extractAllClaims(String token) {

		return Jwts.parserBuilder()
				.setSigningKey(SECRET.getBytes())
				.build()
				.parseClaimsJws(token)
				.getBody();
	}
}
