package com.authkit.project.auth;

/** JWT or refresh token not recognised (403). */
public class InvalidTokenException extends RuntimeException {

	public InvalidTokenException() {
		super(null, null, false, false);
	}

}
