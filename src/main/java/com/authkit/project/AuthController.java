package com.authkit.project;

import java.nio.charset.StandardCharsets;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.authkit.project.auth.AuthCookies;
import com.authkit.project.auth.AuthService;
import com.authkit.project.auth.InvalidCredentialsException;
import com.authkit.project.auth.UsernameTakenException;

import jakarta.servlet.http.HttpServletResponse;

@Controller
public class AuthController {

	private static final int MIN_PASSWORD_LENGTH = 8;
	// BCrypt only uses the first 72 bytes of a password
	private static final int MAX_PASSWORD_BYTES = 72;

	private final AuthService authService;
	private final AuthCookies authCookies;

	public AuthController(AuthService authService, AuthCookies authCookies) {
		this.authService = authService;
		this.authCookies = authCookies;
	}

	@GetMapping("/")
	public String root() {
		return "redirect:/home";
	}

	@GetMapping("/auth")
	public String authPage() {
		return "auth";
	}

	@GetMapping("/home")
	public String home() {
		return "home";
	}

	@PostMapping("/signup")
	public String signup(@RequestParam(defaultValue = "") String name,
			@RequestParam(defaultValue = "") String username,
			@RequestParam(defaultValue = "") String password,
			HttpServletResponse response, Model model) {
		String error = validateSignup(name, username, password);
		if (error != null) {
			return authError(response, model, HttpStatus.BAD_REQUEST, "signup", error);
		}
		try {
			authCookies.setSession(response, authService.signup(name, username, password));
		}
		catch (UsernameTakenException e) {
			return authError(response, model, HttpStatus.CONFLICT, "signup", "An account with this email already exists");
		}
		return "redirect:/home";
	}

	@PostMapping("/login")
	public String login(@RequestParam(defaultValue = "") String username,
			@RequestParam(defaultValue = "") String password,
			HttpServletResponse response, Model model) {
		try {
			authCookies.setSession(response, authService.login(username, password));
		}
		catch (InvalidCredentialsException e) {
			return authError(response, model, HttpStatus.UNAUTHORIZED, "login", "email or password is incorrect");
		}
		return "redirect:/home";
	}

	@GetMapping("/logout")
	public String logout(@CookieValue(name = AuthCookies.REFRESH_TOKEN, required = false) String refreshToken,
			HttpServletResponse response) {
		authService.logout(refreshToken);
		authCookies.clear(response);
		return "logout";
	}

	private static String validateSignup(String name, String username, String password) {
		if (name.isBlank()) {
			return "Name is required";
		}
		if (username.isBlank() || username.length() > 255 || !username.contains("@")) {
			return "A valid email is required";
		}
		if (password.length() < MIN_PASSWORD_LENGTH
				|| password.getBytes(StandardCharsets.UTF_8).length > MAX_PASSWORD_BYTES) {
			return "Password must be between 8 and 72 characters";
		}
		return null;
	}

	private static String authError(HttpServletResponse response, Model model, HttpStatus status, String tab,
			String error) {
		response.setStatus(status.value());
		model.addAttribute("activeTab", tab);
		model.addAttribute("error", error);
		return "auth";
	}

}
