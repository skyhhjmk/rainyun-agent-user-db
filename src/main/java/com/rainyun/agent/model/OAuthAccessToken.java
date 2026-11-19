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
@Table(name = "oauth_access_token")
public class OAuthAccessToken extends PanacheEntityBase {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    public Long id;
    @Column(name = "token_hash", nullable = false, unique = true, length = 64)
    public String tokenHash;
    @Column(name = "client_id", nullable = false, length = 80)
    public String clientId;
    @Column(name = "customer_uid", nullable = false)
    public Long customerUid;
    @Column(nullable = false, columnDefinition = "text")
    public String scopes;
    @Column(name = "created_at", nullable = false)
    public Instant createdAt;
    @Column(name = "expires_at", nullable = false)
    public Instant expiresAt;
    @Column(name = "revoked_at")
    public Instant revokedAt;
}
