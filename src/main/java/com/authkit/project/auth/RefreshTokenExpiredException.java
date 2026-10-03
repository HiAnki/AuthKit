package com.authkit.project.auth;

/** Refresh token expired; session is over. */
public class RefreshTokenExpiredException extends RuntimeException {

	public RefreshTokenExpiredException() {
		super(null, null, false, false);
	}

}
