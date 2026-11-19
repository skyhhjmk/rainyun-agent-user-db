package com.rainyun.agent.web;

import com.rainyun.agent.service.SettingsService;
import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Path("/.well-known/oauth-authorization-server")
public class OAuthMetadataResource {
    @Inject SettingsService settings;

    @GET @Produces(MediaType.APPLICATION_JSON)
    public Response metadata() {
        String origin = settings.publicBaseUrl().replaceAll("/+$", "");
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("issuer", origin);
        data.put("authorization_endpoint", origin + "/oauth/authorize");
        data.put("token_endpoint", origin + "/oauth/token");
        data.put("userinfo_endpoint", origin + "/oauth/userinfo");
        data.put("revocation_endpoint", origin + "/oauth/revoke");
        data.put("response_types_supported", List.of("code"));
        data.put("grant_types_supported", List.of("authorization_code"));
        data.put("code_challenge_methods_supported", List.of("S256"));
        data.put("token_endpoint_auth_methods_supported", List.of("client_secret_basic", "client_secret_post", "none"));
        data.put("scopes_supported", List.of("profile", "email"));
        return Response.ok(data).header("Cache-Control", "public, max-age=300").build();
    }
}
