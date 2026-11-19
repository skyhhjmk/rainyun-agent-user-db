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
@Table(name = "customer_account")
public class CustomerAccount extends PanacheEntityBase {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    public Long id;
    @Column(name = "rainyun_uid", nullable = false, unique = true)
    public Long rainyunUid;
    @Column(name = "rainyun_name", nullable = false, length = 160)
    public String rainyunName;
    @Column(length = 254)
    public String email;
    @Column(name = "api_key_ciphertext", nullable = false, columnDefinition = "text")
    public String apiKeyCiphertext;
    @Column(nullable = false, length = 24)
    public String status = "ACTIVE";
    @Column(name = "created_at", nullable = false)
    public Instant createdAt;
    @Column(name = "verified_at", nullable = false)
    public Instant verifiedAt;
}
