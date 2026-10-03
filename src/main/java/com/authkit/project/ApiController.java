package com.authkit.project;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.ResponseBody;

import com.authkit.project.auth.AuthCookies;
import com.authkit.project.auth.AuthService;
import com.authkit.project.auth.ExpiredTokenException;
import com.authkit.project.auth.InvalidTokenException;
import com.authkit.project.auth.RefreshTokenExpiredException;
import com.authkit.project.token.JwtService;

import jakarta.servlet.http.HttpServletResponse;

@Controller
public class ApiController {

	private static final String BEARER_PREFIX = "Bearer ";

	private final AuthService authService;
	private final AuthCookies authCookies;
	private final JwtService jwtService;

	public ApiController(AuthService authService, AuthCookies authCookies, JwtService jwtService) {
		this.authService = authService;
		this.authCookies = authCookies;
		this.jwtService = jwtService;
	}

	/**
	 * Browsers send the JWT in the Cookie header; non-browser clients may use Authorization: Bearer.
	 */
	@GetMapping("/test")
	public String test(@CookieValue(name = AuthCookies.ACCESS_TOKEN, required = false) String cookieJwt,
			@RequestHeader(name = HttpHeaders.AUTHORIZATION, required = false) String authorization,
			Model model) {
		String jwt = cookieJwt;
		if (authorization != null && authorization.startsWith(BEARER_PREFIX)) {
			jwt = authorization.substring(BEARER_PREFIX.length());
		}
		long userId = jwtService.verify(jwt);
		model.addAttribute("user", authService.getUser(userId));
		return "test";
	}

	@GetMapping("/token")
	public ResponseEntity<Void> token(
			@CookieValue(name = AuthCookies.REFRESH_TOKEN, required = false) String refreshToken,
			HttpServletResponse response) {
		try {
			authCookies.setAccessToken(response, authService.refresh(refreshToken));
		}
		catch (RefreshTokenExpiredException e) {
			authCookies.clear(response);
			return ResponseEntity.status(HttpStatus.FOUND).header(HttpHeaders.LOCATION, "/logout").build();
		}
		return ResponseEntity.noContent().build();
	}

	@ExceptionHandler(InvalidTokenException.class)
	@ResponseBody
	public ResponseEntity<String> invalidToken() {
		return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Token not recognised");
	}

	@ExceptionHandler(ExpiredTokenException.class)
	@ResponseBody
	public ResponseEntity<String> expiredToken() {
		return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Token expired");
	}

}
