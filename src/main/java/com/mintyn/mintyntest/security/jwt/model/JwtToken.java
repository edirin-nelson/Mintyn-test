package com.mintyn.mintyntest.security.jwt.model;

import com.mintyn.mintyntest.user_onboarding.model.entity.Users;
import jakarta.persistence.*;
import lombok.*;
import java.util.Date;

@Getter
@Setter
@Builder
@Entity
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "jwtToken")
public class JwtToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    public Long token_id;

    @Column(unique = true, length = 2000)
    public String token;

    public boolean revoked;

    public boolean expired;

    private String refreshToken;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id")
    public Users user;

    private Date generatedAt;

    private Date expiresAt;

    private Date refreshedAt;
}
