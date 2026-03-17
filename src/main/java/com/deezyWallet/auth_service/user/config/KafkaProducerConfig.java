package com.deezyWallet.auth_service.user.config;

import java.util.HashMap;
import java.util.Map;

import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.common.serialization.StringSerializer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.core.DefaultKafkaProducerFactory;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.core.ProducerFactory;
import org.springframework.kafka.support.serializer.JsonSerializer;

/**
 * Kafka producer config for outbound user.events.
 *
 * Settings chosen for reliability:
 *   acks=all       — leader AND all ISR replicas must acknowledge
 *   idempotence    — exactly-once delivery to Kafka (no duplicate on retry)
 *   retries=3      — retry transient broker failures
 *
 * Messages keyed by userId → same user's events land on the same partition
 * → consumers see per-user events in order.
 *
 * WHY no type headers?
 *   spring.json.add.type.headers=false prevents embedding Java class names
 *   in Kafka message headers. Cross-language consumers (Python, Go) would
 *   fail to deserialize if they see Java type headers they don't understand.
 *   Consumers should use the eventType field in the payload, not headers.
 */
@Configuration
public class KafkaProducerConfig {

	@Value("${spring.kafka.bootstrap-servers}")
	private String bootstrapServers;

	@Bean
	public ProducerFactory<String, Object> producerFactory() {
		Map<String, Object> props = new HashMap<>();
		props.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers);
		props.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class);
		props.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, JsonSerializer.class);
		props.put(ProducerConfig.ACKS_CONFIG, "all");
		props.put(ProducerConfig.ENABLE_IDEMPOTENCE_CONFIG, true);
		props.put(ProducerConfig.RETRIES_CONFIG, 3);
		props.put(JsonSerializer.ADD_TYPE_INFO_HEADERS, false);
		return new DefaultKafkaProducerFactory<>(props);
	}

	@Bean
	public KafkaTemplate<String, Object> kafkaTemplate() {
		return new KafkaTemplate<>(producerFactory());
	}
}
