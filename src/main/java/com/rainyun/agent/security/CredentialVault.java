package com.rainyun.agent.security;

import com.rainyun.agent.service.SettingsService;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

@ApplicationScoped
public class CredentialVault {
    private static final SecureRandom RANDOM = new SecureRandom();
    @Inject SettingsService settings;

    public String encrypt(String plaintext) {
        return encryptWithKey(plaintext, settings.credentialEncryptionKey());
    }

    public String decrypt(String ciphertext) {
        return decryptWithKey(ciphertext, settings.credentialEncryptionKey());
    }

    public static String encryptWithKey(String plaintext, String rawKey) {
        try {
            byte[] nonce = new byte[12];
            RANDOM.nextBytes(nonce);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec(rawKey), new GCMParameterSpec(128, nonce));
            byte[] encrypted = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            byte[] payload = new byte[nonce.length + encrypted.length];
            System.arraycopy(nonce, 0, payload, 0, nonce.length);
            System.arraycopy(encrypted, 0, payload, nonce.length, encrypted.length);
            return Base64.getEncoder().encodeToString(payload);
        } catch (Exception e) {
            throw new IllegalStateException("Credential encryption is unavailable", e);
        }
    }

    public static String decryptWithKey(String ciphertext, String rawKey) {
        try {
            byte[] payload = Base64.getDecoder().decode(ciphertext);
            byte[] nonce = java.util.Arrays.copyOfRange(payload, 0, 12);
            byte[] encrypted = java.util.Arrays.copyOfRange(payload, 12, payload.length);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, keySpec(rawKey), new GCMParameterSpec(128, nonce));
            return new String(cipher.doFinal(encrypted), StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new IllegalStateException("Credential could not be decrypted", e);
        }
    }

    private static SecretKeySpec keySpec(String rawKey) throws Exception {
        if (rawKey == null || rawKey.length() < 32) {
            throw new IllegalStateException("Credential encryption key must contain at least 32 characters");
        }
        return new SecretKeySpec(MessageDigest.getInstance("SHA-256").digest(rawKey.getBytes(StandardCharsets.UTF_8)), "AES");
    }
}
