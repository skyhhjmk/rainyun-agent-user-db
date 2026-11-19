package com.rainyun.agent.web;

import com.rainyun.agent.service.SettingsService;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerResponseContext;
import jakarta.ws.rs.container.ContainerResponseFilter;
import jakarta.ws.rs.ext.Provider;
import java.io.IOException;

@Provider
@ApplicationScoped
public class SecurityHeadersFilter implements ContainerResponseFilter {
    @Inject SettingsService settings;

    @Override
    public void filter(ContainerRequestContext request, ContainerResponseContext response) throws IOException {
        response.getHeaders().putSingle("X-Content-Type-Options", "nosniff");
        response.getHeaders().putSingle("X-Frame-Options", "DENY");
        response.getHeaders().putSingle("Referrer-Policy", "strict-origin-when-cross-origin");
        response.getHeaders().putSingle("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
        response.getHeaders().putSingle("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; form-action 'self'; base-uri 'self'; frame-ancestors 'none'; object-src 'none'");
        if (settings.cookieSecure()) response.getHeaders().putSingle("Strict-Transport-Security", "max-age=31536000");
        String path = request.getUriInfo().getPath();
        if (path.startsWith("admin") || path.equals("login") || path.equals("account") || path.startsWith("oauth/")) {
            response.getHeaders().putSingle("Cache-Control", "no-store");
            response.getHeaders().putSingle("Pragma", "no-cache");
        }
    }
}
