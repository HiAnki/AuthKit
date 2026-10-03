package com.authkit.project.token;

import java.time.Instant;
import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.transaction.annotation.Transactional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, String> {

	List<RefreshToken> findByUserId(Long userId);

	@Transactional
	long deleteByExpiresOnBefore(Instant cutoff);

}
