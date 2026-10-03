package com.authkit.project.token;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.stereotype.Service;

import com.authkit.project.auth.ExpiredTokenException;
import com.authkit.project.auth.InvalidTokenException;
import com.authkit.project.config.AuthProperties;

import tools.jackson.databind.json.JsonMapper;

/**
 * HS256 JWTs, each signed with the secret of the refresh token (session) it belongs to.
 *
 * The JWT does not name its refresh token: anyone who can read a JWT would otherwise be able
 * to call /token with it. Instead, verification tries the secrets of the subject's sessions.
 */
@Service
public class JwtService {

	private static final String HEADER = encode("{\"alg\":\"HS256\",\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8));

	private final RefreshTokenRepository refreshTokenRepository;
	private final AuthProperties properties;
	private final Clock clock;
	private final JsonMapper jsonMapper = JsonMapper.builder().build();

	public JwtService(RefreshTokenRepository refreshTokenRepository, AuthProperties properties, Clock clock) {
		this.refreshTokenRepository = refreshTokenRepository;
		this.properties = properties;
		this.clock = clock;
	}

	public String issue(RefreshToken session) {
		Instant now = clock.instant();
		JwtClaims claims = new JwtClaims(String.valueOf(session.getUserId()), now.getEpochSecond(),
				now.plus(properties.jwtTtl()).getEpochSecond());
		String signingInput = HEADER + "." + encode(jsonMapper.writeValueAsBytes(claims));
		return signingInput + "." + encode(hmac(session.getSecret(), signingInput));
	}

	/**
	 * @return the authenticated user id
	 * @throws InvalidTokenException if the token is malformed or its signature is not recognised
	 * @throws ExpiredTokenException if the signature is valid but the token has expired
	 */
	public long verify(String jwt) {
		String[] parts = jwt == null ? new String[0] : jwt.split("\\.", -1);
		if (parts.length != 3 || !HEADER.equals(parts[0])) {
			throw new InvalidTokenException();
		}

		JwtClaims claims;
		long userId;
		byte[] signature;
		try {
			claims = jsonMapper.readValue(Base64.getUrlDecoder().decode(parts[1]), JwtClaims.class);
			userId = Long.parseLong(claims.sub());
			signature = Base64.getUrlDecoder().decode(parts[2]);
		}
		catch (RuntimeException e) {
			throw new InvalidTokenException();
		}

		String signingInput = parts[0] + "." + parts[1];
		boolean signatureValid = refreshTokenRepository.findByUserId(userId).stream()
				.anyMatch(session -> MessageDigest.isEqual(hmac(session.getSecret(), signingInput), signature));
		if (!signatureValid) {
			throw new InvalidTokenException();
		}
		if (clock.instant().getEpochSecond() >= claims.exp()) {
			throw new ExpiredTokenException();
		}
		return userId;
	}

	private static byte[] hmac(byte[] key, String data) {
		try {
			Mac mac = Mac.getInstance("HmacSHA256");
			mac.init(new SecretKeySpec(key, "HmacSHA256"));
			return mac.doFinal(data.getBytes(StandardCharsets.US_ASCII));
		}
		catch (GeneralSecurityException e) {
			throw new IllegalStateException("HmacSHA256 unavailable", e);
		}
	}

	private static String encode(byte[] bytes) {
		return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
	}

	record JwtClaims(String sub, long iat, long exp) {
	}

}
