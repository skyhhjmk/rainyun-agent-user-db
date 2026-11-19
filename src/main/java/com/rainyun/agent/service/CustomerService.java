package com.rainyun.agent.service;

import com.rainyun.agent.model.CustomerAccount;
import com.rainyun.agent.rainyun.RainyunClient;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.util.List;

@ApplicationScoped
public class CustomerService {
    @Inject RainyunClient rainyun;
    @Inject CustomerAccountStore accountStore;

    public CustomerAccount link(String apiKey) {
        if (apiKey == null || apiKey.isBlank() || apiKey.length() > 512) throw new IllegalArgumentException("请输入有效的雨云 API Key");
        RainyunClient.Profile profile = rainyun.verify(apiKey.trim());
        if (!profile.realNameVerified()) throw new CustomerEligibilityException(CustomerEligibilityException.Requirement.REAL_NAME);
        if (!profile.wechatBound()) throw new CustomerEligibilityException(CustomerEligibilityException.Requirement.WECHAT);
        return accountStore.upsert(profile, apiKey.trim());
    }

    public CustomerAccount byUid(long uid) { return CustomerAccount.find("rainyunUid", uid).firstResult(); }
    public List<CustomerAccount> all() { return CustomerAccount.find("order by verifiedAt desc").list(); }
    public List<RainyunClient.ResourceView> resources(CustomerAccount account) {
        if (account == null || !"ACTIVE".equals(account.status)) return List.of();
        return rainyun.resources(accountStore.decrypt(account.apiKeyCiphertext));
    }
}
