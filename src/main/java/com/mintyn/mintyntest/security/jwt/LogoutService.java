package com.mintyn.mintyntest.security.jwt;

import com.mintyn.mintyntest.security.jwt.repository.JwtTokenRepository;
import com.mintyn.mintyntest.user_onboarding.repository.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class LogoutService implements LogoutHandler {
    private  final JwtService jwtService;
    private final UserRepository userRepository;
    private final JwtTokenRepository jwtTokenRepository;

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String userEmail;

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return;
        }
        jwt = authHeader.substring(7);
        userEmail = jwtService.extractUserEmail(jwt);

        var customer = userRepository.findVendorByEmail(userEmail)
                .orElse(null);
        var storedToken = jwtTokenRepository.findByToken(jwt)
                .orElse(null);
        if (storedToken == null && customer == null) {
            return;
        }

        assert storedToken != null;
        storedToken.setExpired(true);
        storedToken.setRevoked(true);
        jwtTokenRepository.save(storedToken);
    }
}
