package com.authkit.project.token;

import java.time.Instant;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;

@Entity
@Table(name = "refresh_token", indexes = @Index(name = "idx_refresh_token_user_id", columnList = "userId"))
public class RefreshToken {

	@Id
	@Column(length = 36)
	private String token;

	@Column(nullable = false)
	private Long userId;

	// 256-bit HMAC-SHA256 key used to sign this session's JWTs
	@Column(nullable = false, length = 32)
	private byte[] secret;

	@Column(nullable = false)
	private Instant createdOn;

	@Column(nullable = false)
	private Instant expiresOn;

	protected RefreshToken() {
	}

	public RefreshToken(String token, Long userId, byte[] secret, Instant createdOn, Instant expiresOn) {
		this.token = token;
		this.userId = userId;
		this.secret = secret;
		this.createdOn = createdOn;
		this.expiresOn = expiresOn;
	}

	public boolean isExpired(Instant now) {
		return !now.isBefore(expiresOn);
	}

	public String getToken() {
		return token;
	}

	public Long getUserId() {
		return userId;
	}

	public byte[] getSecret() {
		return secret;
	}

	public Instant getCreatedOn() {
		return createdOn;
	}

	public Instant getExpiresOn() {
		return expiresOn;
	}

}
