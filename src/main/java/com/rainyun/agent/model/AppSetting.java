package com.rainyun.agent.model;

import io.quarkus.hibernate.orm.panache.PanacheEntityBase;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;

@Entity
@Table(name = "app_setting")
public class AppSetting extends PanacheEntityBase {
    @Id
    @Column(name = "setting_key", nullable = false, length = 100)
    public String settingKey;

    @Column(name = "setting_value", nullable = false, columnDefinition = "text")
    public String settingValue;

    @Column(name = "updated_at", nullable = false)
    public Instant updatedAt;
}
