package com.mintyn.mintyntest.user_onboarding.repository;

import com.mintyn.mintyntest.user_onboarding.model.entity.Users;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<Users, Long> {
    Optional<Users> findVendorByEmail(String username);
}
