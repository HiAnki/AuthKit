package com.authkit.project;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Duration;
import java.util.List;
import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.http.HttpHeaders;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import com.authkit.project.auth.AuthCookies;
import com.authkit.project.token.RefreshTokenRepository;

import jakarta.servlet.http.Cookie;

@SpringBootTest
class AuthFlowTests {

	@TestConfiguration
	static class ClockConfig {

		@Bean
		@Primary
		MutableClock mutableClock() {
			return new MutableClock();
		}

	}

	@Autowired
	private WebApplicationContext context;

	@Autowired
	private MutableClock clock;

	@Autowired
	private RefreshTokenRepository refreshTokenRepository;

	private MockMvc mockMvc;

	@BeforeEach
	void setUp() {
		mockMvc = MockMvcBuilders.webAppContextSetup(context).build();
	}

	@Test
	void signupSetsSecureCookiesAndRedirectsHome() throws Exception {
		MvcResult result = signup(uniqueEmail(), "password123");

		assertThat(result.getResponse().getStatus()).isEqualTo(302);
		assertThat(result.getResponse().getRedirectedUrl()).isEqualTo("/home");
		List<String> setCookies = result.getResponse().getHeaders(HttpHeaders.SET_COOKIE);
		assertThat(setCookies).hasSize(2).allSatisfy(cookie -> assertThat(cookie)
				.contains("HttpOnly").contains("Secure").contains("SameSite=Strict"));
	}

	@Test
	void testEndpointAcceptsValidJwt() throws Exception {
		MvcResult signup = signup(uniqueEmail(), "password123");

		mockMvc.perform(get("/test").cookie(jwtCookie(signup)))
				.andExpect(status().isOk())
				.andExpect(content().string(org.hamcrest.Matchers.containsString("Test User")));
	}

	@Test
	void testEndpointAcceptsBearerHeader() throws Exception {
		MvcResult signup = signup(uniqueEmail(), "password123");

		mockMvc.perform(get("/test").header(HttpHeaders.AUTHORIZATION, "Bearer " + jwtCookie(signup).getValue()))
				.andExpect(status().isOk());
	}

	@Test
	void testEndpointRejectsMissingOrTamperedJwtWith403() throws Exception {
		mockMvc.perform(get("/test")).andExpect(status().isForbidden());

		String jwt = jwtCookie(signup(uniqueEmail(), "password123")).getValue();
		String tampered = jwt.substring(0, jwt.length() - 2) + (jwt.endsWith("AA") ? "BB" : "AA");
		mockMvc.perform(get("/test").cookie(new Cookie(AuthCookies.ACCESS_TOKEN, tampered)))
				.andExpect(status().isForbidden());
		mockMvc.perform(get("/test").cookie(new Cookie(AuthCookies.ACCESS_TOKEN, "garbage")))
				.andExpect(status().isForbidden());
	}

	@Test
	void expiredJwtGives401AndTokenEndpointIssuesFreshOne() throws Exception {
		MvcResult signup = signup(uniqueEmail(), "password123");
		clock.advance(Duration.ofMinutes(6));

		mockMvc.perform(get("/test").cookie(jwtCookie(signup))).andExpect(status().isUnauthorized());

		MvcResult refresh = mockMvc.perform(get("/token").cookie(refreshCookie(signup)))
				.andExpect(status().isNoContent())
				.andReturn();
		Cookie freshJwt = refresh.getResponse().getCookie(AuthCookies.ACCESS_TOKEN);
		assertThat(freshJwt).isNotNull();

		mockMvc.perform(get("/test").cookie(freshJwt)).andExpect(status().isOk());
	}

	@Test
	void tokenEndpointRejectsUnknownRefreshTokenWith403() throws Exception {
		mockMvc.perform(get("/token")).andExpect(status().isForbidden());
		mockMvc.perform(get("/token").cookie(new Cookie(AuthCookies.REFRESH_TOKEN, UUID.randomUUID().toString())))
				.andExpect(status().isForbidden());
	}

	@Test
	void expiredRefreshTokenIsDeletedAndRedirectsToLogout() throws Exception {
		MvcResult signup = signup(uniqueEmail(), "password123");
		Cookie refreshCookie = refreshCookie(signup);
		clock.advance(Duration.ofDays(8));

		mockMvc.perform(get("/token").cookie(refreshCookie))
				.andExpect(status().isFound())
				.andExpect(redirectedUrl("/logout"));

		assertThat(refreshTokenRepository.findById(refreshCookie.getValue())).isEmpty();
	}

	@Test
	void loginWithCorrectPasswordStartsNewSession() throws Exception {
		String email = uniqueEmail();
		signup(email, "password123");

		MvcResult login = mockMvc.perform(post("/login").param("username", email).param("password", "password123"))
				.andExpect(status().isFound())
				.andExpect(redirectedUrl("/home"))
				.andReturn();

		mockMvc.perform(get("/test").cookie(jwtCookie(login))).andExpect(status().isOk());
	}

	@Test
	void loginFailuresUseTheSameMessage() throws Exception {
		String email = uniqueEmail();
		signup(email, "password123");

		mockMvc.perform(post("/login").param("username", email).param("password", "wrong-password"))
				.andExpect(status().isUnauthorized())
				.andExpect(header().doesNotExist(HttpHeaders.SET_COOKIE))
				.andExpect(content().string(org.hamcrest.Matchers.containsString("email or password is incorrect")));
		mockMvc.perform(post("/login").param("username", uniqueEmail()).param("password", "password123"))
				.andExpect(status().isUnauthorized())
				.andExpect(content().string(org.hamcrest.Matchers.containsString("email or password is incorrect")));
	}

	@Test
	void duplicateSignupIsRejected() throws Exception {
		String email = uniqueEmail();
		signup(email, "password123");

		assertThat(signup(email.toUpperCase(), "password123").getResponse().getStatus()).isEqualTo(409);
	}

	@Test
	void logoutDeletesRefreshTokenAndClearsCookies() throws Exception {
		MvcResult signup = signup(uniqueEmail(), "password123");
		Cookie refreshCookie = refreshCookie(signup);

		MvcResult logout = mockMvc.perform(get("/logout").cookie(refreshCookie))
				.andExpect(status().isOk())
				.andReturn();

		assertThat(refreshTokenRepository.findById(refreshCookie.getValue())).isEmpty();
		assertThat(logout.getResponse().getHeaders(HttpHeaders.SET_COOKIE)).allSatisfy(
				cookie -> assertThat(cookie).contains("Max-Age=0"));
		mockMvc.perform(get("/test").cookie(jwtCookie(signup))).andExpect(status().isForbidden());
	}

	private MvcResult signup(String email, String password) throws Exception {
		return mockMvc.perform(post("/signup")
				.param("name", "Test User")
				.param("username", email)
				.param("password", password))
				.andReturn();
	}

	private static Cookie jwtCookie(MvcResult result) {
		return result.getResponse().getCookie(AuthCookies.ACCESS_TOKEN);
	}

	private static Cookie refreshCookie(MvcResult result) {
		return result.getResponse().getCookie(AuthCookies.REFRESH_TOKEN);
	}

	private static String uniqueEmail() {
		return "user-" + UUID.randomUUID() + "@example.com";
	}

}
