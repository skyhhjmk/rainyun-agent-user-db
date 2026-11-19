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
@Table(name = "oauth_client")
public class OAuthClient extends PanacheEntityBase {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    public Long id;
    @Column(name = "client_id", nullable = false, unique = true, length = 80)
    public String clientId;
    @Column(name = "display_name", nullable = false, length = 160)
    public String displayName;
    @Column(name = "client_secret_hash", nullable = false, length = 256)
    public String clientSecretHash;
    @Column(name = "redirect_uris", nullable = false, columnDefinition = "text")
    public String redirectUris;
    @Column(name = "allowed_scopes", nullable = false, columnDefinition = "text")
    public String allowedScopes;
    @Column(name = "public_client", nullable = false)
    public boolean publicClient;
    @Column(nullable = false)
    public boolean active = true;
    @Column(name = "created_at", nullable = false)
    public Instant createdAt;
}
