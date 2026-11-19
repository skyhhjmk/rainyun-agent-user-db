package com.rainyun.agent.web;

import com.rainyun.agent.model.CustomerAccount;
import com.rainyun.agent.security.SessionService;
import com.rainyun.agent.service.CustomerService;
import com.rainyun.agent.service.CustomerEligibilityException;
import io.quarkus.qute.Template;
import io.quarkus.qute.TemplateInstance;
import io.quarkus.qute.Location;
import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.CookieParam;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.NewCookie;
import jakarta.ws.rs.core.Response;
import java.net.URI;

@Path("/")
public class LoginResource {
    @Inject @Location("login.html") Template login;
    @Inject @Location("account.html") Template account;
    @Inject CustomerService customers;
    @Inject SessionService sessions;

    @GET
    @Produces(MediaType.TEXT_HTML)
    public Response home(@CookieParam("ry_session") String cookie) {
        if (sessions.isAdmin(cookie)) return Response.seeOther(URI.create("/admin/dashboard")).build();
        Long uid = sessions.customerUid(cookie);
        CustomerAccount customer = uid == null ? null : customers.byUid(uid);
        return Response.seeOther(URI.create(customer != null && "ACTIVE".equals(customer.status) ? "/account" : "/login")).build();
    }

    @GET
    @Path("login")
    @Produces(MediaType.TEXT_HTML)
    public TemplateInstance login(@jakarta.ws.rs.QueryParam("return_to") String returnTo,
                                  @jakarta.ws.rs.QueryParam("error") String error,
                                  @CookieParam("ry_session") String cookie) {
        Long uid = sessions.customerUid(cookie);
        CustomerAccount customer = uid == null ? null : customers.byUid(uid);
        if (customer != null && "ACTIVE".equals(customer.status)) {
            if ("/account".equals(safeReturnTo(returnTo))) return account.data("name", customer.rainyunName).data("uid", customer.rainyunUid).data("verifiedAt", customer.verifiedAt);
        }
        return login.data("returnTo", safeReturnTo(returnTo)).data("error", message(error));
    }

    @POST
    @Path("login")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response login(@FormParam("api_key") String apiKey, @FormParam("return_to") String returnTo) {
        try {
            CustomerAccount customer = customers.link(apiKey);
            return Response.seeOther(URI.create(safeReturnTo(returnTo)))
                    .header("Set-Cookie", sessions.createCustomerCookie(customer.rainyunUid)).build();
        } catch (RuntimeException e) {
            String safe = safeReturnTo(returnTo);
            String reason = e instanceof CustomerEligibilityException eligibility
                    ? eligibility.requirement() == CustomerEligibilityException.Requirement.REAL_NAME ? "real_name" : "wechat"
                    : "verify";
            return Response.seeOther(URI.create("/login?error=" + reason + "&return_to=" + java.net.URLEncoder.encode(safe, java.nio.charset.StandardCharsets.UTF_8))).build();
        }
    }

    @GET
    @Path("account")
    @Produces(MediaType.TEXT_HTML)
    public Response account(@CookieParam("ry_session") String cookie) {
        Long uid = sessions.customerUid(cookie);
        CustomerAccount customer = uid == null ? null : customers.byUid(uid);
        if (customer == null || !"ACTIVE".equals(customer.status)) return Response.seeOther(URI.create("/login")).build();
        return Response.ok(account.data("name", customer.rainyunName).data("uid", customer.rainyunUid)
                .data("verifiedAt", customer.verifiedAt)).build();
    }

    @POST
    @Path("logout")
    public Response logout() { return Response.seeOther(URI.create("/login")).header("Set-Cookie", sessions.clearCookie()).build(); }

    private String safeReturnTo(String value) {
        if (value == null || value.isBlank() || !value.startsWith("/") || value.startsWith("//") || value.contains("\\")) return "/account";
        return value;
    }
    private String message(String error) {
        return switch (error == null ? "" : error) {
            case "real_name" -> "此账号尚未完成雨云实名认证，请完成认证后再绑定。";
            case "wechat" -> "此账号尚未绑定微信，请先在雨云账号设置中绑定微信。";
            case "verify" -> "校验失败，请确认 API Key 有效且账号上级 UID 属于本代理商。";
            default -> "";
        };
    }
}
