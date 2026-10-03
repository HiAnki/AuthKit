package com.authkit.project.config;

import java.time.Duration;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

@ConfigurationProperties("authkit")
public record AuthProperties(
		@DefaultValue("5m") Duration jwtTtl,
		@DefaultValue("7d") Duration refreshTokenTtl,
		@DefaultValue("true") boolean cookieSecure) {
}
