package com.authkit.project.auth;

/** JWT signature valid but expired (401). */
public class ExpiredTokenException extends RuntimeException {

	public ExpiredTokenException() {
		super(null, null, false, false);
	}

}
