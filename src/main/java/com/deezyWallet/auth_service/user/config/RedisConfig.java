package com.deezyWallet.auth_service.user.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.StringRedisSerializer;

/**
 * Redis configuration for User Service.
 *
 * All keys and values are plain strings.
 *
 * Use cases:
 *   - OTP storage (key: otp:{purpose}:{phone}, value: otpCode)
 *   - Session storage (key: user:session:{sessionId}, value: userId)
 *   - Token blacklist (key: user:blacklist:{jti}, value: "1")
 *   - MFA pending state (key: user:mfa_pending:{userId}, value: userId)
 *
 * WHY StringRedisSerializer for both key and value?
 *   All our stored values are strings — OTP codes, UUIDs, status flags.
 *   Using Java serialization (the default) would bloat the value with
 *   class metadata. StringSerializer is smaller, faster, and human-readable
 *   in Redis CLI / monitoring tools.
 */
@Configuration
public class RedisConfig {

	@Bean
	public RedisTemplate<String, String> redisTemplate(RedisConnectionFactory factory) {
		RedisTemplate<String, String> template = new RedisTemplate<>();
		template.setConnectionFactory(factory);
		template.setKeySerializer(new StringRedisSerializer());
		template.setValueSerializer(new StringRedisSerializer());
		template.setHashKeySerializer(new StringRedisSerializer());
		template.setHashValueSerializer(new StringRedisSerializer());
		template.afterPropertiesSet();
		return template;
	}
}
