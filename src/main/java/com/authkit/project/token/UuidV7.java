package com.authkit.project.token;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.UUID;

/**
 * RFC 9562 UUIDv7: 48-bit Unix millisecond timestamp followed by random bits.
 * Java 17 has no built-in generator for this version.
 */
public final class UuidV7 {

	private static final SecureRandom RANDOM = new SecureRandom();

	private UuidV7() {
	}

	public static UUID generate(long epochMillis) {
		byte[] bytes = new byte[16];
		RANDOM.nextBytes(bytes);
		for (int i = 0; i < 6; i++) {
			bytes[i] = (byte) (epochMillis >>> (40 - 8 * i));
		}
		bytes[6] = (byte) ((bytes[6] & 0x0F) | 0x70);
		bytes[8] = (byte) ((bytes[8] & 0x3F) | 0x80);
		ByteBuffer buffer = ByteBuffer.wrap(bytes);
		return new UUID(buffer.getLong(), buffer.getLong());
	}

}
