package com.authkit.project.auth;

/** Unknown username or wrong password. */
public class InvalidCredentialsException extends RuntimeException {

	public InvalidCredentialsException() {
		super(null, null, false, false);
	}

}
