package com.authkit.project.auth;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.Locale;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.authkit.project.config.AuthProperties;
import com.authkit.project.token.JwtService;
import com.authkit.project.token.RefreshToken;
import com.authkit.project.token.RefreshTokenRepository;
import com.authkit.project.token.UuidV7;
import com.authkit.project.user.User;
import com.authkit.project.user.UserRepository;

@Service
public class AuthService {

	private static final Logger log = LoggerFactory.getLogger(AuthService.class);

	private final UserRepository userRepository;
	private final RefreshTokenRepository refreshTokenRepository;
	private final JwtService jwtService;
	private final PasswordEncoder passwordEncoder;
	private final AuthProperties properties;
	private final Clock clock;
	private final SecureRandom secureRandom = new SecureRandom();

	// Compared against when the username is unknown, so both failure paths cost one bcrypt check
	private final String dummyPasswordHash;

	public AuthService(UserRepository userRepository, RefreshTokenRepository refreshTokenRepository,
			JwtService jwtService, PasswordEncoder passwordEncoder, AuthProperties properties, Clock clock) {
		this.userRepository = userRepository;
		this.refreshTokenRepository = refreshTokenRepository;
		this.jwtService = jwtService;
		this.passwordEncoder = passwordEncoder;
		this.properties = properties;
		this.clock = clock;
		this.dummyPasswordHash = passwordEncoder.encode("dummy-password");
	}

	public Session signup(String name, String username, String password) {
		String normalizedUsername = normalize(username);
		if (userRepository.existsByUsername(normalizedUsername)) {
			throw new UsernameTakenException();
		}
		User user;
		try {
			user = userRepository.save(new User(name.trim(), normalizedUsername, passwordEncoder.encode(password),
					clock.instant()));
		}
		catch (DataIntegrityViolationException e) {
			// Lost a race with a concurrent signup for the same username
			throw new UsernameTakenException();
		}
		return startSession(user);
	}

	public Session login(String username, String password) {
		User user = userRepository.findByUsername(normalize(username)).orElse(null);
		if (user == null) {
			passwordEncoder.matches(password, dummyPasswordHash);
			throw new InvalidCredentialsException();
		}
		if (!passwordEncoder.matches(password, user.getPassword())) {
			throw new InvalidCredentialsException();
		}
		return startSession(user);
	}

	/** Issues a fresh JWT for the session identified by the given refresh token. */
	public String refresh(String refreshTokenValue) {
		RefreshToken refreshToken = refreshTokenValue == null ? null
				: refreshTokenRepository.findById(refreshTokenValue).orElse(null);
		if (refreshToken == null) {
			throw new InvalidTokenException();
		}
		if (refreshToken.isExpired(clock.instant())) {
			refreshTokenRepository.delete(refreshToken);
			throw new RefreshTokenExpiredException();
		}
		return jwtService.issue(refreshToken);
	}

	public void logout(String refreshTokenValue) {
		if (refreshTokenValue != null) {
			refreshTokenRepository.deleteById(refreshTokenValue);
		}
	}

	public User getUser(long userId) {
		return userRepository.findById(userId).orElseThrow(InvalidTokenException::new);
	}

	@Scheduled(fixedRateString = "PT1H")
	public void purgeExpiredRefreshTokens() {
		long deleted = refreshTokenRepository.deleteByExpiresOnBefore(clock.instant());
		if (deleted > 0) {
			log.info("Purged {} expired refresh tokens", deleted);
		}
	}

	private Session startSession(User user) {
		Instant now = clock.instant();
		byte[] secret = new byte[32];
		secureRandom.nextBytes(secret);
		RefreshToken refreshToken = refreshTokenRepository.save(new RefreshToken(
				UuidV7.generate(now.toEpochMilli()).toString(), user.getId(), secret, now,
				now.plus(properties.refreshTokenTtl())));
		return new Session(refreshToken.getToken(), jwtService.issue(refreshToken));
	}

	private static String normalize(String username) {
		return username.trim().toLowerCase(Locale.ROOT);
	}

	public record Session(String refreshToken, String jwt) {
	}

}
