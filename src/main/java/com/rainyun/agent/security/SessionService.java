package com.rainyun.agent.security;

import com.rainyun.agent.service.SettingsService;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Base64;

@ApplicationScoped
public class SessionService {
    @Inject SettingsService settings;

    public String createAdminCookie() { return create("admin", "admin", 8 * 60 * 60); }
    public String createCustomerCookie(long uid) { return create("customer", Long.toString(uid), 12 * 60 * 60); }
    public String clearCookie() { return "ry_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax" + (settings.cookieSecure() ? "; Secure" : ""); }
    public boolean isAdmin(String value) { Session s = read(value); return s != null && s.kind.equals("admin"); }
    public String csrfToken(String value) { return read(value) == null ? "" : sign("csrf|" + value); }
    public boolean validCsrf(String value, String csrf) {
        if (read(value) == null || csrf == null) return false;
        return MessageDigest.isEqual(csrfToken(value).getBytes(StandardCharsets.US_ASCII), csrf.getBytes(StandardCharsets.US_ASCII));
    }
    public Long customerUid(String value) {
        Session s = read(value);
        if (s == null || !s.kind.equals("customer")) return null;
        try { return Long.parseLong(s.subject); } catch (NumberFormatException ignored) { return null; }
    }

    private String create(String kind, String subject, long lifetimeSeconds) {
        String payload = kind + "|" + subject + "|" + Instant.now().plusSeconds(lifetimeSeconds).getEpochSecond();
        String encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(payload.getBytes(StandardCharsets.UTF_8));
        return "ry_session=" + encoded + "." + sign(encoded) + "; Path=/; Max-Age=" + lifetimeSeconds
                + "; HttpOnly; SameSite=Lax" + (settings.cookieSecure() ? "; Secure" : "");
    }

    private Session read(String value) {
        String secret = settings.sessionSecret();
        if (secret == null || secret.length() < 32 || value == null) return null;
        try {
            String[] chunks = value.split("\\.", -1);
            if (chunks.length != 2 || !MessageDigest.isEqual(sign(chunks[0]).getBytes(StandardCharsets.US_ASCII), chunks[1].getBytes(StandardCharsets.US_ASCII))) return null;
            String[] fields = new String(Base64.getUrlDecoder().decode(chunks[0]), StandardCharsets.UTF_8).split("\\|", -1);
            if (fields.length != 3 || Instant.now().getEpochSecond() >= Long.parseLong(fields[2])) return null;
            return new Session(fields[0], fields[1]);
        } catch (Exception ignored) { return null; }
    }

    private String sign(String value) {
        try {
            String secret = settings.sessionSecret();
            if (secret == null || secret.length() < 32) return "";
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(mac.doFinal(value.getBytes(StandardCharsets.US_ASCII)));
        } catch (Exception e) { throw new IllegalStateException("Unable to sign session", e); }
    }

    private record Session(String kind, String subject) {}
}
