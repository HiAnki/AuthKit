package com.authkit.project.auth;

import java.time.Duration;

import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

import com.authkit.project.config.AuthProperties;

import jakarta.servlet.http.HttpServletResponse;

@Component
public class AuthCookies {

	public static final String ACCESS_TOKEN = "access_token";
	public static final String REFRESH_TOKEN = "refresh_token";

	private final AuthProperties properties;

	public AuthCookies(AuthProperties properties) {
		this.properties = properties;
	}

	public void setSession(HttpServletResponse response, AuthService.Session session) {
		setAccessToken(response, session.jwt());
		add(response, REFRESH_TOKEN, session.refreshToken(), properties.refreshTokenTtl());
	}

	/**
	 * The JWT itself is valid for only a few minutes, but the cookie must outlive it: if the
	 * browser dropped it at expiry, /test would see no token (403) instead of an expired one
	 * (401), and the page would never know to call /token.
	 */
	public void setAccessToken(HttpServletResponse response, String jwt) {
		add(response, ACCESS_TOKEN, jwt, properties.refreshTokenTtl());
	}

	public void clear(HttpServletResponse response) {
		add(response, ACCESS_TOKEN, "", Duration.ZERO);
		add(response, REFRESH_TOKEN, "", Duration.ZERO);
	}

	private void add(HttpServletResponse response, String name, String value, Duration maxAge) {
		ResponseCookie cookie = ResponseCookie.from(name, value)
				.httpOnly(true)
				.secure(properties.cookieSecure())
				.sameSite("Strict")
				.path("/")
				.maxAge(maxAge)
				.build();
		response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
	}

}
