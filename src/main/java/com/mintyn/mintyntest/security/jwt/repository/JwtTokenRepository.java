package com.mintyn.mintyntest.security.jwt.repository;


import com.mintyn.mintyntest.security.jwt.model.JwtToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface JwtTokenRepository extends JpaRepository<JwtToken, Long> {
    Optional<JwtToken> findByToken(String token);
}
