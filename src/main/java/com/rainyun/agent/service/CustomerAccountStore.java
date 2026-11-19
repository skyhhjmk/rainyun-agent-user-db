package com.rainyun.agent.service;

import com.rainyun.agent.model.CustomerAccount;
import com.rainyun.agent.rainyun.RainyunClient;
import com.rainyun.agent.security.CredentialVault;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.transaction.Transactional;
import java.time.Instant;

@ApplicationScoped
public class CustomerAccountStore {
    @Inject CredentialVault vault;

    @Transactional
    public CustomerAccount upsert(RainyunClient.Profile profile, String apiKey) {
        CustomerAccount account = CustomerAccount.find("rainyunUid", profile.uid()).firstResult();
        if (account != null && !"ACTIVE".equals(account.status)) throw new IllegalArgumentException("此客户账号已被代理商停用");
        Instant now = Instant.now();
        if (account == null) {
            account = new CustomerAccount();
            account.rainyunUid = profile.uid();
            account.createdAt = now;
        }
        account.rainyunName = profile.name().isBlank() ? "Rainyun " + profile.uid() : profile.name();
        account.email = profile.email();
        account.apiKeyCiphertext = vault.encrypt(apiKey);
        account.status = "ACTIVE";
        account.verifiedAt = now;
        account.persist();
        return account;
    }

    public String decrypt(String ciphertext) { return vault.decrypt(ciphertext); }
}
