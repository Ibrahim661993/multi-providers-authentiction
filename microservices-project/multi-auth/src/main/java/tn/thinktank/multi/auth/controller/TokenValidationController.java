package tn.thinktank.multi.auth.controller;


import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;
import tn.thinktank.multi.auth.entity.Tenant;
import tn.thinktank.multi.auth.service.TenantService;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@RestController
@RequiredArgsConstructor
public class TokenValidationController {

    private final TenantService tenantService;

    @PostMapping("/auth/validate")
    public ResponseEntity<ValidationResponse> validateToken(
            @RequestHeader("Authorization") String authorizationHeader,
            @RequestHeader("X-Tenant-ID") String tenantId) {

        try {
            Tenant tenant = tenantService.getTenant(tenantId);
            String token = authorizationHeader.replace("Bearer ", "");
            System.out.println(" Tenant ID: " + tenantId);
            System.out.println(" Issuer URI: " + tenant.getIssuerUri());
            System.out.println(" Token: " + token);

            JwtDecoder jwtDecoder = JwtDecoders.fromIssuerLocation(tenant.getIssuerUri());
            Jwt jwt = jwtDecoder.decode(token); // Exception si invalide

            // Extraire le username (preferred_username ou sub fallback)
            String username = jwt.getClaimAsString("preferred_username");
            if (username == null) {
                username = jwt.getSubject();
            }

            // Extraire les rôles
            Set<String> roles = extractRoles(jwt);

            return ResponseEntity.ok(new ValidationResponse(true, username, roles));
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.ok(new ValidationResponse(false, null, Set.of()));
        }
    }

    private Set<String> extractRoles(Jwt jwt) {
        try {
            Map<String, Object> resourceAccess = jwt.getClaim("resource_access");
            if (resourceAccess != null) {
                // Exemple Keycloak
                for (Object value : resourceAccess.values()) {
                    if (value instanceof Map map) {
                        Object rolesObj = map.get("roles");
                        if (rolesObj instanceof List list) {
                            return (Set<String>) list.stream()
                                    .filter(String.class::isInstance)
                                    .map(String.class::cast)
                                    .collect(Collectors.toSet());
                        }
                    }
                }
            }
            // Fallback : claim "roles" (exemple Okta)
            List<String> roles = jwt.getClaimAsStringList("roles");
            if (roles != null) {
                return Set.copyOf(roles);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return Set.of();
    }

    public record ValidationResponse(boolean active, String username, Collection<String> roles) {}
}
