package com.rainyun.agent.web;

import com.rainyun.agent.model.AdminAccount;
import com.rainyun.agent.model.CustomerAccount;
import com.rainyun.agent.model.OAuthClient;
import com.rainyun.agent.rainyun.RainyunClient;
import com.rainyun.agent.security.PasswordHasher;
import com.rainyun.agent.security.SessionService;
import com.rainyun.agent.service.CustomerService;
import com.rainyun.agent.service.SettingsService;
import io.quarkus.qute.Template;
import io.quarkus.qute.TemplateInstance;
import io.quarkus.qute.Location;
import jakarta.inject.Inject;
import jakarta.transaction.Transactional;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.CookieParam;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.net.URI;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

@Path("/admin")
public class AdminResource {
    @Inject @Location("admin/login.html") Template adminLogin;
    @Inject @Location("admin/dashboard.html") Template dashboard;
    @Inject @Location("admin/resources.html") Template resources;
    @Inject @Location("admin/settings.html") Template settingsPage;
    @Inject SessionService sessions;
    @Inject CustomerService customers;
    @Inject SettingsService settings;

    @GET
    @Produces(MediaType.TEXT_HTML)
    public Response root(@CookieParam("ry_session") String cookie) {
        return sessions.isAdmin(cookie) ? Response.seeOther(URI.create("/admin/dashboard")).build()
                : Response.seeOther(URI.create("/admin/login")).build();
    }

    @GET @Path("login") @Produces(MediaType.TEXT_HTML)
    public TemplateInstance login(@QueryParam("error") String error) {
        String message = "";
        if (!settings.hasAdminAccount()) {
            message = "管理员账号尚未初始化，请在首次启动时通过环境变量 APP_ADMIN_USERNAME 和 APP_ADMIN_PASSWORD_HASH 初始化。";
        } else if ("1".equals(error)) {
            message = "账号或密码不正确。";
        }
        return adminLogin.data("error", message);
    }

    @POST @Path("login") @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response login(@FormParam("username") String username, @FormParam("password") String password) {
        AdminAccount admin = settings.findAdminByUsername(username);
        if (admin != null && PasswordHasher.verify(admin.passwordHash, password)) {
            return Response.seeOther(URI.create("/admin/dashboard")).header("Set-Cookie", sessions.createAdminCookie()).build();
        }
        return Response.seeOther(URI.create("/admin/login?error=1")).build();
    }

    @GET @Path("dashboard") @Produces(MediaType.TEXT_HTML)
    public Response dashboard(@CookieParam("ry_session") String cookie) {
        if (!sessions.isAdmin(cookie)) return Response.seeOther(URI.create("/admin/login")).build();
        return Response.ok(dashboardPage(cookie, "", "")).type(MediaType.TEXT_HTML_TYPE).build();
    }

    @POST @Path("clients") @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Transactional
    public Response createClient(@CookieParam("ry_session") String cookie,
                                 @FormParam("display_name") String displayName,
                                 @FormParam("redirect_uris") String redirectUris,
                                 @FormParam("public_client") String publicClientValue,
                                 @FormParam("profile") String profile,
                                 @FormParam("email") String email,
                                 @FormParam("csrf_token") String csrf) {
        if (!sessions.isAdmin(cookie) || !sessions.validCsrf(cookie, csrf)) return Response.seeOther(URI.create("/admin/login")).build();
        boolean publicClient = "on".equals(publicClientValue);
        List<String> redirects = validatedRedirects(redirectUris);
        if (displayName == null || displayName.isBlank() || displayName.length() > 160 || redirects.isEmpty()) {
            return Response.ok(dashboardPage(cookie, "", "").data("formError", "请填写名称，并提供至少一个有效的 HTTPS 或 localhost 回调地址。"))
                    .type(MediaType.TEXT_HTML_TYPE).build();
        }
        OAuthClient client = new OAuthClient();
        client.clientId = "ry_" + com.rainyun.agent.security.Hashing.randomToken(18);
        client.displayName = displayName.trim();
        client.redirectUris = String.join("\n", redirects);
        List<String> scopes = new ArrayList<>();
        if (profile != null) scopes.add("profile");
        if (email != null) scopes.add("email");
        if (scopes.isEmpty()) scopes.add("profile");
        client.allowedScopes = String.join(" ", scopes);
        client.publicClient = publicClient;
        String secret = publicClient ? "" : com.rainyun.agent.security.Hashing.randomToken(36);
        client.clientSecretHash = publicClient ? null : PasswordHasher.hash(secret);
        client.active = true;
        client.createdAt = Instant.now();
        client.persist();
        return Response.ok(dashboardPage(cookie, secret, client.clientId)).type(MediaType.TEXT_HTML_TYPE).build();
    }

    @POST @Path("clients/{clientId}/disable") @Consumes(MediaType.APPLICATION_FORM_URLENCODED) @Transactional
    public Response disableClient(@CookieParam("ry_session") String cookie, @PathParam("clientId") String clientId,
                                  @FormParam("csrf_token") String csrf) {
        if (!sessions.isAdmin(cookie) || !sessions.validCsrf(cookie, csrf)) return Response.seeOther(URI.create("/admin/login")).build();
        OAuthClient client = OAuthClient.find("clientId", clientId).firstResult();
        if (client != null) client.active = false;
        return Response.seeOther(URI.create("/admin/dashboard")).build();
    }

    @POST @Path("customers/{uid}/disable") @Consumes(MediaType.APPLICATION_FORM_URLENCODED) @Transactional
    public Response disableCustomer(@CookieParam("ry_session") String cookie, @PathParam("uid") long uid,
                                    @FormParam("csrf_token") String csrf) {
        if (!sessions.isAdmin(cookie) || !sessions.validCsrf(cookie, csrf)) return Response.seeOther(URI.create("/admin/login")).build();
        CustomerAccount customer = customers.byUid(uid);
        if (customer != null) customer.status = "DISABLED";
        return Response.seeOther(URI.create("/admin/dashboard")).build();
    }

    @POST @Path("customers/{uid}/enable") @Consumes(MediaType.APPLICATION_FORM_URLENCODED) @Transactional
    public Response enableCustomer(@CookieParam("ry_session") String cookie, @PathParam("uid") long uid,
                                   @FormParam("csrf_token") String csrf) {
        if (!sessions.isAdmin(cookie) || !sessions.validCsrf(cookie, csrf)) return Response.seeOther(URI.create("/admin/login")).build();
        CustomerAccount customer = customers.byUid(uid);
        if (customer != null) customer.status = "ACTIVE";
        return Response.seeOther(URI.create("/admin/dashboard")).build();
    }

    @GET @Path("customers/{uid}/resources") @Produces(MediaType.TEXT_HTML)
    public Response customerResources(@CookieParam("ry_session") String cookie, @PathParam("uid") long uid) {
        if (!sessions.isAdmin(cookie)) return Response.seeOther(URI.create("/admin/login")).build();
        CustomerAccount customer = customers.byUid(uid);
        if (customer == null || !"ACTIVE".equals(customer.status)) return Response.status(404).entity("Customer not found").build();
        List<RainyunClient.ResourceView> items = customers.resources(customer);
        return Response.ok(resources.data("customer", customer).data("items", items)).build();
    }

    private List<String> validatedRedirects(String raw) {
        if (raw == null || raw.length() > 8000) return List.of();
        List<String> valid = new ArrayList<>();
        for (String line : raw.split("\\R")) {
            String value = line.trim();
            if (value.isEmpty()) continue;
            try {
                URI uri = URI.create(value);
                boolean local = "localhost".equalsIgnoreCase(uri.getHost()) || "127.0.0.1".equals(uri.getHost()) || "[::1]".equals(uri.getHost());
                boolean secureWeb = "https".equalsIgnoreCase(uri.getScheme()) && uri.getHost() != null;
                boolean loopback = local && "http".equalsIgnoreCase(uri.getScheme());
                boolean privateScheme = uri.getScheme() != null && uri.getScheme().matches("[A-Za-z][A-Za-z0-9.+-]{2,}")
                        && uri.getScheme().contains(".") && uri.getPath() != null && !uri.getPath().isBlank();
                if ((secureWeb || loopback || privateScheme) && uri.getUserInfo() == null && uri.getFragment() == null) valid.add(value);
            } catch (Exception ignored) { }
        }
        return valid.stream().distinct().toList();
    }

    @GET @Path("settings") @Produces(MediaType.TEXT_HTML)
    public Response settings(@CookieParam("ry_session") String cookie,
                             @QueryParam("saved") String saved,
                             @QueryParam("accountSaved") String accountSaved) {
        if (!sessions.isAdmin(cookie)) return Response.seeOther(URI.create("/admin/login")).build();
        String notice = "";
        if ("1".equals(saved)) notice = "系统配置已保存到数据库并立即生效。";
        else if ("1".equals(accountSaved)) notice = "管理员账号信息已更新。";
        return Response.ok(settingsView(cookie, notice, "")).type(MediaType.TEXT_HTML_TYPE).build();
    }

    @POST @Path("settings") @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response updateSettings(@CookieParam("ry_session") String cookie,
                                   @FormParam("api_base_url") String apiBaseUrl,
                                   @FormParam("agent_uid") String agentUidRaw,
                                   @FormParam("timeout_seconds") String timeoutSecondsRaw,
                                   @FormParam("public_base_url") String publicBaseUrl,
                                   @FormParam("cookie_secure") String cookieSecureRaw,
                                   @FormParam("session_secret") String sessionSecret,
                                   @FormParam("credential_encryption_key") String credentialEncryptionKey,
                                   @FormParam("csrf_token") String csrf) {
        if (!sessions.isAdmin(cookie) || !sessions.validCsrf(cookie, csrf)) {
            return Response.seeOther(URI.create("/admin/login")).build();
        }
        try {
            long agentUid = Long.parseLong(agentUidRaw == null ? "0" : agentUidRaw.trim());
            long timeoutSeconds = Long.parseLong(timeoutSecondsRaw == null ? "8" : timeoutSecondsRaw.trim());
            boolean cookieSecure = "on".equals(cookieSecureRaw);
            boolean rotatingSession = sessionSecret != null && !sessionSecret.trim().isEmpty();
            settings.updateSettings(apiBaseUrl, agentUid, timeoutSeconds, publicBaseUrl, cookieSecure, sessionSecret, credentialEncryptionKey);
            Response.ResponseBuilder builder = Response.seeOther(URI.create("/admin/settings?saved=1"));
            if (rotatingSession) {
                builder.header("Set-Cookie", sessions.createAdminCookie());
            }
            return builder.build();
        } catch (NumberFormatException e) {
            return Response.ok(settingsView(cookie, "", "代理商 UID 和超时时间必须是有效的整数。")).type(MediaType.TEXT_HTML_TYPE).build();
        } catch (RuntimeException e) {
            return Response.ok(settingsView(cookie, "", e.getMessage())).type(MediaType.TEXT_HTML_TYPE).build();
        }
    }

    @POST @Path("settings/account") @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response updateAdminAccount(@CookieParam("ry_session") String cookie,
                                       @FormParam("current_password") String currentPassword,
                                       @FormParam("username") String username,
                                       @FormParam("new_password") String newPassword,
                                       @FormParam("confirm_password") String confirmPassword,
                                       @FormParam("csrf_token") String csrf) {
        if (!sessions.isAdmin(cookie) || !sessions.validCsrf(cookie, csrf)) {
            return Response.seeOther(URI.create("/admin/login")).build();
        }
        try {
            settings.updateAdminAccount(currentPassword, username, newPassword, confirmPassword);
            return Response.seeOther(URI.create("/admin/settings?accountSaved=1")).build();
        } catch (RuntimeException e) {
            return Response.ok(settingsView(cookie, "", e.getMessage())).type(MediaType.TEXT_HTML_TYPE).build();
        }
    }

    private TemplateInstance settingsView(String cookie, String notice, String error) {
        AdminAccount admin = settings.primaryAdmin();
        return settingsPage
                .data("apiBaseUrl", settings.rainyunApiBaseUrl())
                .data("agentUid", settings.rainyunAgentUid())
                .data("timeoutSeconds", settings.rainyunTimeoutSeconds())
                .data("publicBaseUrl", settings.publicBaseUrl())
                .data("cookieSecure", settings.cookieSecure())
                .data("adminUsername", admin == null ? "" : admin.username)
                .data("csrfToken", sessions.csrfToken(cookie))
                .data("notice", notice == null ? "" : notice)
                .data("error", error == null ? "" : error);
    }

    private TemplateInstance dashboardPage(String cookie, String newSecret, String newClientId) {
        List<AccountRow> accountRows = customers.all().stream().map(a -> new AccountRow(a.rainyunUid, a.rainyunName,
                a.email == null ? "" : a.email, a.status, a.verifiedAt.toString())).toList();
        List<ClientRow> clientRows = OAuthClient.<OAuthClient>list("order by createdAt desc").stream().map(c ->
                new ClientRow(c.clientId, c.displayName, c.redirectUris, c.allowedScopes, c.active, c.publicClient)).toList();
        return dashboard.data("accounts", accountRows).data("clients", clientRows)
                .data("newSecret", newSecret == null ? "" : newSecret).data("newClientId", newClientId == null ? "" : newClientId)
                .data("csrfToken", sessions.csrfToken(cookie)).data("formError", "");
    }

    public record AccountRow(long uid, String name, String email, String status, String verifiedAt) {}
    public record ClientRow(String clientId, String name, String redirectUris, String scopes, boolean active, boolean publicClient) {}
}
