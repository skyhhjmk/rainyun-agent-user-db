package com.rainyun.agent.service;

import com.rainyun.agent.model.AdminAccount;
import com.rainyun.agent.model.AppSetting;
import com.rainyun.agent.model.CustomerAccount;
import com.rainyun.agent.security.CredentialVault;
import com.rainyun.agent.security.Hashing;
import com.rainyun.agent.security.PasswordHasher;
import io.quarkus.runtime.StartupEvent;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.transaction.Transactional;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

@ApplicationScoped
public class SettingsService {
    public static final String KEY_RAINYUN_API_BASE_URL = "rainyun.api-base-url";
    public static final String KEY_RAINYUN_AGENT_UID = "rainyun.agent-uid";
    public static final String KEY_RAINYUN_TIMEOUT_SECONDS = "rainyun.timeout-seconds";
    public static final String KEY_PUBLIC_BASE_URL = "app.public-base-url";
    public static final String KEY_COOKIE_SECURE = "app.cookie-secure";
    public static final String KEY_SESSION_SECRET = "app.session-secret";
    public static final String KEY_CREDENTIAL_ENCRYPTION_KEY = "app.credential-encryption-key";

    @ConfigProperty(name = "rainyun.api-base-url", defaultValue = "https://api.v2.rainyun.com")
    String initApiBaseUrl;
    @ConfigProperty(name = "rainyun.agent-uid", defaultValue = "0")
    long initAgentUid;
    @ConfigProperty(name = "rainyun.timeout-seconds", defaultValue = "8")
    long initTimeoutSeconds;
    @ConfigProperty(name = "app.public-base-url", defaultValue = "http://localhost:8080")
    String initPublicBaseUrl;
    @ConfigProperty(name = "app.cookie-secure", defaultValue = "true")
    boolean initCookieSecure;
    @ConfigProperty(name = "app.session-secret")
    Optional<String> initSessionSecret;
    @ConfigProperty(name = "app.credential-encryption-key")
    Optional<String> initCredentialKey;
    @ConfigProperty(name = "app.admin.username", defaultValue = "admin")
    String initAdminUsername;
    @ConfigProperty(name = "app.admin.password-hash")
    Optional<String> initAdminPasswordHash;

    private final Map<String, String> cache = new ConcurrentHashMap<>();

    @Transactional
    void onStart(@Observes StartupEvent event) {
        for (AppSetting row : AppSetting.<AppSetting>listAll()) {
            cache.put(row.settingKey, row.settingValue);
        }
        seedIfAbsent(KEY_RAINYUN_API_BASE_URL, cleanUrl(initApiBaseUrl, "https://api.v2.rainyun.com"));
        seedIfAbsent(KEY_RAINYUN_AGENT_UID, Long.toString(Math.max(0L, initAgentUid)));
        seedIfAbsent(KEY_RAINYUN_TIMEOUT_SECONDS, Long.toString(clampTimeout(initTimeoutSeconds)));
        seedIfAbsent(KEY_PUBLIC_BASE_URL, cleanUrl(initPublicBaseUrl, "http://localhost:8080"));
        seedIfAbsent(KEY_COOKIE_SECURE, Boolean.toString(initCookieSecure));
        seedIfAbsent(KEY_SESSION_SECRET, validSecretOrGenerate(initSessionSecret.orElse("")));
        seedIfAbsent(KEY_CREDENTIAL_ENCRYPTION_KEY, validSecretOrGenerate(initCredentialKey.orElse("")));

        if (AdminAccount.count() == 0) {
            String hash = initAdminPasswordHash.map(String::trim).orElse("");
            String username = initAdminUsername == null ? "" : initAdminUsername.trim();
            if (!hash.isEmpty() && !username.isEmpty()) {
                Instant now = Instant.now();
                AdminAccount admin = new AdminAccount();
                admin.username = username;
                admin.passwordHash = hash;
                admin.createdAt = now;
                admin.updatedAt = now;
                admin.persist();
            }
        }
    }

    public String rainyunApiBaseUrl() {
        return get(KEY_RAINYUN_API_BASE_URL, "https://api.v2.rainyun.com");
    }

    public long rainyunAgentUid() {
        try {
            return Long.parseLong(get(KEY_RAINYUN_AGENT_UID, "0"));
        } catch (NumberFormatException ignored) {
            return 0L;
        }
    }

    public long rainyunTimeoutSeconds() {
        try {
            return clampTimeout(Long.parseLong(get(KEY_RAINYUN_TIMEOUT_SECONDS, "8")));
        } catch (NumberFormatException ignored) {
            return 8L;
        }
    }

    public String publicBaseUrl() {
        return get(KEY_PUBLIC_BASE_URL, "http://localhost:8080");
    }

    public boolean cookieSecure() {
        return Boolean.parseBoolean(get(KEY_COOKIE_SECURE, "true"));
    }

    public String sessionSecret() {
        return get(KEY_SESSION_SECRET, "");
    }

    public String credentialEncryptionKey() {
        return get(KEY_CREDENTIAL_ENCRYPTION_KEY, "");
    }

    public boolean hasAdminAccount() {
        return AdminAccount.count() > 0;
    }

    public AdminAccount findAdminByUsername(String username) {
        if (username == null || username.isBlank()) return null;
        return AdminAccount.find("username", username.trim()).firstResult();
    }

    public AdminAccount primaryAdmin() {
        return AdminAccount.<AdminAccount>find("order by id asc").firstResult();
    }

    @Transactional
    public void updateSettings(String apiBaseUrl,
                               long agentUid,
                               long timeoutSeconds,
                               String publicBaseUrl,
                               boolean cookieSecure,
                               String newSessionSecret,
                               String newEncryptionKey) {
        String normalizedApiBase = validateHttpUrl(apiBaseUrl, "雨云 API 根地址");
        String normalizedPublicBase = validateHttpUrl(publicBaseUrl, "对外根地址");
        if (agentUid < 0) throw new IllegalArgumentException("代理商 UID 不能为负数");
        if (timeoutSeconds < 1 || timeoutSeconds > 60) throw new IllegalArgumentException("API 超时时间需在 1 到 60 秒之间");

        String trimmedSession = newSessionSecret == null ? "" : newSessionSecret.trim();
        if (!trimmedSession.isEmpty() && trimmedSession.length() < 32) {
            throw new IllegalArgumentException("Session 密钥至少需要 32 个字符");
        }

        String trimmedEncKey = newEncryptionKey == null ? "" : newEncryptionKey.trim();
        if (!trimmedEncKey.isEmpty() && trimmedEncKey.length() < 32) {
            throw new IllegalArgumentException("API Key 加密主密钥至少需要 32 个字符");
        }

        if (!trimmedEncKey.isEmpty()) {
            String oldKey = credentialEncryptionKey();
            if (!trimmedEncKey.equals(oldKey)) {
                List<CustomerAccount> accounts = CustomerAccount.listAll();
                for (CustomerAccount account : accounts) {
                    String plaintext = CredentialVault.decryptWithKey(account.apiKeyCiphertext, oldKey);
                    account.apiKeyCiphertext = CredentialVault.encryptWithKey(plaintext, trimmedEncKey);
                }
                upsert(KEY_CREDENTIAL_ENCRYPTION_KEY, trimmedEncKey);
            }
        }

        if (!trimmedSession.isEmpty()) {
            upsert(KEY_SESSION_SECRET, trimmedSession);
        }

        upsert(KEY_RAINYUN_API_BASE_URL, normalizedApiBase);
        upsert(KEY_RAINYUN_AGENT_UID, Long.toString(agentUid));
        upsert(KEY_RAINYUN_TIMEOUT_SECONDS, Long.toString(timeoutSeconds));
        upsert(KEY_PUBLIC_BASE_URL, normalizedPublicBase);
        upsert(KEY_COOKIE_SECURE, Boolean.toString(cookieSecure));
    }

    @Transactional
    public void updateAdminAccount(String currentPassword, String newUsername, String newPassword, String confirmPassword) {
        AdminAccount admin = primaryAdmin();
        if (admin == null) throw new IllegalStateException("管理员账号尚未初始化");
        if (currentPassword == null || !PasswordHasher.verify(admin.passwordHash, currentPassword)) {
            throw new IllegalArgumentException("当前密码不正确");
        }
        String trimmedUsername = newUsername == null ? "" : newUsername.trim();
        if (trimmedUsername.isEmpty() || trimmedUsername.length() > 100) {
            throw new IllegalArgumentException("管理员账号不能为空且长度不能超过 100 个字符");
        }
        String nextPassword = newPassword == null ? "" : newPassword;
        if (!nextPassword.isEmpty()) {
            if (nextPassword.length() < 8) throw new IllegalArgumentException("新密码至少需要 8 个字符");
            if (!nextPassword.equals(confirmPassword)) throw new IllegalArgumentException("两次输入的新密码不一致");
            admin.passwordHash = PasswordHasher.hash(nextPassword);
        }
        admin.username = trimmedUsername;
        admin.updatedAt = Instant.now();
    }

    private String get(String key, String fallback) {
        String cached = cache.get(key);
        if (cached != null) return cached;
        AppSetting row = AppSetting.findById(key);
        if (row != null) {
            cache.put(key, row.settingValue);
            return row.settingValue;
        }
        return fallback;
    }

    private void seedIfAbsent(String key, String value) {
        if (!cache.containsKey(key)) {
            upsert(key, value);
        }
    }

    private void upsert(String key, String value) {
        Instant now = Instant.now();
        AppSetting row = AppSetting.findById(key);
        if (row == null) {
            row = new AppSetting();
            row.settingKey = key;
        }
        row.settingValue = value;
        row.updatedAt = now;
        row.persist();
        cache.put(key, value);
    }

    private static String validSecretOrGenerate(String candidate) {
        String trimmed = candidate == null ? "" : candidate.trim();
        return trimmed.length() >= 32 ? trimmed : Hashing.randomToken(32);
    }

    private static long clampTimeout(long value) {
        return Math.max(1L, Math.min(60L, value));
    }

    private static String cleanUrl(String candidate, String fallback) {
        try {
            return validateHttpUrl(candidate, "URL");
        } catch (IllegalArgumentException ignored) {
            return fallback;
        }
    }

    private static String validateHttpUrl(String raw, String label) {
        if (raw == null || raw.isBlank()) throw new IllegalArgumentException(label + "不能为空");
        String trimmed = raw.trim().replaceAll("/+$", "");
        try {
            URI uri = URI.create(trimmed);
            String scheme = uri.getScheme();
            if ((!"http".equalsIgnoreCase(scheme) && !"https".equalsIgnoreCase(scheme)) || uri.getHost() == null || uri.getHost().isBlank()) {
                throw new IllegalArgumentException(label + "必须是有效的 HTTP 或 HTTPS 地址");
            }
            return trimmed;
        } catch (IllegalArgumentException e) {
            if (e.getMessage() != null && e.getMessage().startsWith(label)) throw e;
            throw new IllegalArgumentException(label + "格式无效");
        }
    }
}
