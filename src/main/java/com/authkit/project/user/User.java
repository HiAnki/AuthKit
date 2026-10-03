package com.authkit.project.user;

import java.time.Instant;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

// "user" is a reserved word in H2 (and others), so the table name is quoted
@Entity
@Table(name = "`user`")
public class User {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	@Column(nullable = false)
	private String name;

	@Column(nullable = false, unique = true, length = 255)
	private String username;

	@Column(nullable = false)
	private String password;

	@Enumerated(EnumType.STRING)
	@Column(name = "two_fa_method")
	private TwoFAMethod twoFAMethod;

	@Column(nullable = false)
	private Instant registeredOn;

	protected User() {
	}

	public User(String name, String username, String passwordHash, Instant registeredOn) {
		this.name = name;
		this.username = username;
		this.password = passwordHash;
		this.registeredOn = registeredOn;
	}

	public Long getId() {
		return id;
	}

	public String getName() {
		return name;
	}

	public String getUsername() {
		return username;
	}

	public String getPassword() {
		return password;
	}

	public TwoFAMethod getTwoFAMethod() {
		return twoFAMethod;
	}

	public Instant getRegisteredOn() {
		return registeredOn;
	}

}
