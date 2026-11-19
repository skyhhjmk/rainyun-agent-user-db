package com.rainyun.agent.model;

import io.quarkus.hibernate.orm.panache.PanacheEntityBase;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;

@Entity
@Table(name = "oauth_authorization_code")
public class OAuthAuthorizationCode extends PanacheEntityBase {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    public Long id;
    @Column(name = "code_hash", nullable = false, unique = true, length = 64)
    public String codeHash;
    @Column(name = "client_id", nullable = false, length = 80)
    public String clientId;
    @Column(name = "customer_uid", nullable = false)
    public Long customerUid;
    @Column(name = "redirect_uri", nullable = false, columnDefinition = "text")
    public String redirectUri;
    @Column(nullable = false, columnDefinition = "text")
    public String scopes;
    @Column(name = "code_challenge", nullable = false, length = 128)
    public String codeChallenge;
    @Column(name = "code_challenge_method", nullable = false, length = 16)
    public String codeChallengeMethod;
    @Column(name = "expires_at", nullable = false)
    public Instant expiresAt;
    @Column(name = "consumed_at")
    public Instant consumedAt;
}
