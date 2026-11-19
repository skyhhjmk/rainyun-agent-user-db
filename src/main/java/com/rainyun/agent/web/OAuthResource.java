package com.rainyun.agent.web;

import com.rainyun.agent.model.CustomerAccount;
import com.rainyun.agent.model.OAuthAccessToken;
import com.rainyun.agent.model.OAuthAuthorizationCode;
import com.rainyun.agent.model.OAuthClient;
import com.rainyun.agent.security.Hashing;
import com.rainyun.agent.security.PasswordHasher;
import com.rainyun.agent.security.SessionService;
import com.rainyun.agent.service.CustomerService;
import io.quarkus.qute.Template;
import io.quarkus.qute.TemplateInstance;
import io.quarkus.qute.Location;
import jakarta.inject.Inject;
import jakarta.persistence.LockModeType;
import jakarta.transaction.Transactional;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.CookieParam;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

@Path("/oauth")
public class OAuthResource {
    @Inject @Location("oauth/consent.html") Template consent;
    @Inject SessionService sessions;
    @Inject CustomerService customers;

    @GET @Path("/authorize") @Produces(MediaType.TEXT_HTML)
    public Response authorize(@jakarta.ws.rs.QueryParam("response_type") String responseType,
                              @jakarta.ws.rs.QueryParam("client_id") String clientId,
                              @jakarta.ws.rs.QueryParam("redirect_uri") String redirectUri,
                              @jakarta.ws.rs.QueryParam("scope") String requestedScope,
                              @jakarta.ws.rs.QueryParam("state") String state,
                              @jakarta.ws.rs.QueryParam("code_challenge") String challenge,
                              @jakarta.ws.rs.QueryParam("code_challenge_method") String challengeMethod,
                              @CookieParam("ry_session") String cookie,
                              @jakarta.ws.rs.core.Context jakarta.ws.rs.core.UriInfo uriInfo) {
        OAuthClient client = OAuthClient.find("clientId = ?1 and active = true", clientId).firstResult();
        if (client == null) return oauthError("invalid_client", "Unknown or disabled client", 400);
        if (!isRedirectAllowed(client, redirectUri)) return oauthError("invalid_request", "redirect_uri is not registered", 400);
        if (!"code".equals(responseType)) return redirectError(redirectUri, "unsupported_response_type", state);
        if (!validText(state, 1024)) return redirectError(redirectUri, "invalid_request", null);
        if (challenge == null || challenge.length() < 43 || challenge.length() > 128 || !challenge.matches("[A-Za-z0-9._~-]+")
                || !"S256".equals(challengeMethod)) return redirectError(redirectUri, "invalid_request", state);
        List<String> scopes = scopeList(requestedScope, client.allowedScopes);
        if (scopes == null) return redirectError(redirectUri, "invalid_scope", state);
        Long uid = sessions.customerUid(cookie);
        CustomerAccount customer = uid == null ? null : customers.byUid(uid);
        if (customer == null || !"ACTIVE".equals(customer.status)) {
            String current = uriInfo.getRequestUri().getRawPath();
            if (uriInfo.getRequestUri().getRawQuery() != null) current += "?" + uriInfo.getRequestUri().getRawQuery();
            return Response.seeOther(URI.create("/login?return_to=" + enc(current))).build();
        }
        return Response.ok(consent.data("clientName", client.displayName).data("uid", customer.rainyunUid)
                .data("scopes", scopes).data("clientId", client.clientId).data("redirectUri", redirectUri)
                .data("state", state == null ? "" : state).data("scope", String.join(" ", scopes))
                .data("challenge", challenge).data("challengeMethod", challengeMethod).data("csrfToken", sessions.csrfToken(cookie)))
                .type(MediaType.TEXT_HTML_TYPE).build();
    }

    @POST @Path("/authorize/decision") @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Transactional
    public Response decision(@CookieParam("ry_session") String cookie,
                             @FormParam("decision") String decision,
                             @FormParam("client_id") String clientId,
                             @FormParam("redirect_uri") String redirectUri,
                             @FormParam("scope") String scope,
                             @FormParam("state") String state,
                             @FormParam("code_challenge") String challenge,
                             @FormParam("code_challenge_method") String method,
                             @FormParam("csrf_token") String csrf) {
        if (!sessions.validCsrf(cookie, csrf)) return oauthError("invalid_request", "Authorization session expired", 400);
        OAuthClient client = OAuthClient.find("clientId = ?1 and active = true", clientId).firstResult();
        if (client == null || !isRedirectAllowed(client, redirectUri)) return oauthError("invalid_request", "Invalid authorization request", 400);
        if (!validText(state, 1024)) return redirectError(redirectUri, "invalid_request", null);
        Long uid = sessions.customerUid(cookie);
        CustomerAccount customer = uid == null ? null : customers.byUid(uid);
        if (customer == null || !"ACTIVE".equals(customer.status)) return Response.seeOther(URI.create("/login")).build();
        if (!"approve".equals(decision)) return redirectError(redirectUri, "access_denied", state);
        List<String> scopes = scopeList(scope, client.allowedScopes);
        if (scopes == null || challenge == null || !"S256".equals(method) || challenge.length() < 43 || challenge.length() > 128)
            return redirectError(redirectUri, "invalid_request", state);
        String rawCode = Hashing.randomToken(32);
        OAuthAuthorizationCode code = new OAuthAuthorizationCode();
        code.codeHash = Hashing.sha256(rawCode);
        code.clientId = clientId;
        code.customerUid = customer.rainyunUid;
        code.redirectUri = redirectUri;
        code.scopes = String.join(" ", scopes);
        code.codeChallenge = challenge;
        code.codeChallengeMethod = method;
        code.expiresAt = Instant.now().plusSeconds(180);
        code.persist();
        return redirectCode(redirectUri, rawCode, state);
    }

    @POST @Path("/token") @Consumes(MediaType.APPLICATION_FORM_URLENCODED) @Produces(MediaType.APPLICATION_JSON)
    @Transactional
    public Response token(@FormParam("grant_type") String grantType,
                          @FormParam("code") String codeValue,
                          @FormParam("redirect_uri") String redirectUri,
                          @FormParam("client_id") String formClientId,
                          @FormParam("client_secret") String formSecret,
                          @FormParam("code_verifier") String verifier,
                          @HeaderParam("Authorization") String authorization) {
        if (!"authorization_code".equals(grantType)) return oauthJsonError("unsupported_grant_type", "Only authorization_code is supported", 400);
        ClientCredentials credentials = credentials(authorization, formClientId, formSecret);
        OAuthClient client = credentials == null ? null : OAuthClient.find("clientId = ?1 and active = true", credentials.clientId).firstResult();
        if (client == null || !clientAuthenticated(client, credentials)) return oauthJsonError("invalid_client", "Client authentication failed", 401);
        if (codeValue == null || redirectUri == null || verifier == null || verifier.length() < 43 || verifier.length() > 128
                || !verifier.matches("[A-Za-z0-9._~-]+")) return oauthJsonError("invalid_request", "Invalid authorization code request", 400);
        OAuthAuthorizationCode code = OAuthAuthorizationCode.find("codeHash", Hashing.sha256(codeValue))
                .withLock(LockModeType.PESSIMISTIC_WRITE).firstResult();
        if (code == null || code.consumedAt != null || Instant.now().isAfter(code.expiresAt)
                || !client.clientId.equals(code.clientId) || !redirectUri.equals(code.redirectUri)
                || !pkceMatches(verifier, code.codeChallenge)) return oauthJsonError("invalid_grant", "Authorization code is invalid or expired", 400);
        CustomerAccount customer = customers.byUid(code.customerUid);
        if (customer == null || !"ACTIVE".equals(customer.status)) return oauthJsonError("invalid_grant", "Customer account is unavailable", 400);
        code.consumedAt = Instant.now();
        String rawToken = Hashing.randomToken(32);
        OAuthAccessToken token = new OAuthAccessToken();
        token.tokenHash = Hashing.sha256(rawToken);
        token.clientId = client.clientId;
        token.customerUid = code.customerUid;
        token.scopes = code.scopes;
        token.createdAt = Instant.now();
        token.expiresAt = Instant.now().plusSeconds(3600);
        token.persist();
        return oauthResponse(Map.of("access_token", rawToken, "token_type", "Bearer", "expires_in", 3600,
                "scope", code.scopes));
    }

    @GET @Path("/userinfo") @Produces(MediaType.APPLICATION_JSON)
    public Response userinfo(@HeaderParam("Authorization") String authorization) {
        String raw = bearer(authorization);
        if (raw == null) return bearerError();
        OAuthAccessToken token = OAuthAccessToken.find("tokenHash", Hashing.sha256(raw)).firstResult();
        if (token == null || token.revokedAt != null || Instant.now().isAfter(token.expiresAt)) return bearerError();
        OAuthClient client = OAuthClient.find("clientId", token.clientId).firstResult();
        if (client == null || !client.active) return bearerError();
        CustomerAccount customer = customers.byUid(token.customerUid);
        if (customer == null || !"ACTIVE".equals(customer.status)) return bearerError();
        Set<String> scopes = Set.copyOf(words(token.scopes));
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("sub", Long.toString(customer.rainyunUid));
        if (scopes.contains("profile")) claims.put("name", customer.rainyunName);
        if (scopes.contains("email") && customer.email != null && !customer.email.isBlank()) claims.put("email", customer.email);
        return Response.ok(claims).header("Cache-Control", "no-store").build();
    }

    @POST @Path("/revoke") @Consumes(MediaType.APPLICATION_FORM_URLENCODED) @Produces(MediaType.APPLICATION_JSON)
    @Transactional
    public Response revoke(@FormParam("token") String rawToken,
                           @FormParam("client_id") String formClientId,
                           @FormParam("client_secret") String formSecret,
                           @HeaderParam("Authorization") String authorization) {
        ClientCredentials credentials = credentials(authorization, formClientId, formSecret);
        OAuthClient client = credentials == null ? null : OAuthClient.find("clientId = ?1 and active = true", credentials.clientId).firstResult();
        if (client == null || !clientAuthenticated(client, credentials)) return oauthJsonError("invalid_client", "Client authentication failed", 401);
        if (rawToken != null) {
            OAuthAccessToken token = OAuthAccessToken.find("tokenHash", Hashing.sha256(rawToken)).firstResult();
            if (token != null && token.clientId.equals(client.clientId)) token.revokedAt = Instant.now();
        }
        return oauthResponse(Map.of());
    }

    private ClientCredentials credentials(String authorization, String formId, String formSecret) {
        if (authorization != null && authorization.regionMatches(true, 0, "Basic ", 0, 6)) {
            try {
                String decoded = new String(Base64.getDecoder().decode(authorization.substring(6).trim()), StandardCharsets.UTF_8);
                int colon = decoded.indexOf(':');
                if (colon < 1) return null;
                return new ClientCredentials(URLDecoder.decode(decoded.substring(0, colon), StandardCharsets.UTF_8),
                        URLDecoder.decode(decoded.substring(colon + 1), StandardCharsets.UTF_8));
            } catch (Exception ignored) { return null; }
        }
        return formId == null ? null : new ClientCredentials(formId, formSecret == null ? "" : formSecret);
    }

    private boolean clientAuthenticated(OAuthClient client, ClientCredentials credentials) {
        if (client.publicClient) return credentials.secret.isEmpty();
        return credentials.secret != null && PasswordHasher.verify(client.clientSecretHash, credentials.secret);
    }

    private boolean pkceMatches(String verifier, String challenge) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII));
            String calculated = Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
            return MessageDigest.isEqual(calculated.getBytes(StandardCharsets.US_ASCII), challenge.getBytes(StandardCharsets.US_ASCII));
        } catch (Exception e) { return false; }
    }

    private List<String> scopeList(String requested, String allowed) {
        List<String> scopes = requested == null || requested.isBlank() ? List.of("profile") : words(requested);
        Set<String> allowedScopes = Set.copyOf(words(allowed));
        if (scopes.isEmpty() || scopes.stream().anyMatch(s -> !allowedScopes.contains(s) || !(s.equals("profile") || s.equals("email")))) return null;
        return scopes.stream().distinct().toList();
    }
    private List<String> words(String value) { return value == null ? List.of() : java.util.Arrays.stream(value.trim().split("\\s+")).filter(s -> !s.isBlank()).toList(); }
    private boolean isRedirectAllowed(OAuthClient client, String redirectUri) {
        if (redirectUri == null || redirectUri.length() > 2048) return false;
        return List.of(client.redirectUris.split("\\R")).contains(redirectUri);
    }
    private boolean validText(String value, int max) { return value == null || (value.length() <= max && !value.contains("\r") && !value.contains("\n")); }
    private String enc(String value) { return java.net.URLEncoder.encode(value, StandardCharsets.UTF_8); }
    private Response redirectCode(String uri, String code, String state) {
        UriBuilder builder = UriBuilder.fromUri(uri).queryParam("code", code);
        if (state != null) builder.queryParam("state", state);
        return Response.seeOther(builder.build()).build();
    }
    private Response redirectError(String uri, String error, String state) {
        UriBuilder builder = UriBuilder.fromUri(uri).queryParam("error", error);
        if (state != null) builder.queryParam("state", state);
        return Response.seeOther(builder.build()).build();
    }
    private Response oauthError(String error, String description, int status) {
        return Response.status(status).type(MediaType.APPLICATION_JSON_TYPE).entity(Map.of("error", error, "error_description", description)).build();
    }
    private Response oauthJsonError(String error, String description, int status) {
        return Response.status(status).type(MediaType.APPLICATION_JSON_TYPE).entity(Map.of("error", error, "error_description", description))
                .header("Cache-Control", "no-store").header("Pragma", "no-cache").build();
    }
    private Response oauthResponse(Map<String, ?> data) {
        return Response.ok(data).header("Cache-Control", "no-store").header("Pragma", "no-cache").build();
    }
    private String bearer(String authorization) {
        if (authorization == null || !authorization.regionMatches(true, 0, "Bearer ", 0, 7)) return null;
        String token = authorization.substring(7).trim();
        return token.matches("[A-Za-z0-9_-]{32,128}") ? token : null;
    }
    private Response bearerError() { return Response.status(401).entity(Map.of("error", "invalid_token")).header("WWW-Authenticate", "Bearer").header("Cache-Control", "no-store").build(); }
    private record ClientCredentials(String clientId, String secret) {}
}
