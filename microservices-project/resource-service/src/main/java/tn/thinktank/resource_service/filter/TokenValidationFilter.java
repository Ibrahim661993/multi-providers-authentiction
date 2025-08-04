
package tn.thinktank.resource_service.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.reactive.function.client.WebClient;

import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
@Slf4j
public class TokenValidationFilter extends OncePerRequestFilter {

    private final WebClient.Builder webClientBuilder;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        String tenantHeader = request.getHeader("X-Tenant-ID");
        log.info("Authorization header: {}", authHeader);
        log.info("X-Tenant-ID header: {}", tenantHeader);

        if (authHeader == null || tenantHeader == null) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.getWriter().write("{\"error\":\"Missing Authorization or X-Tenant-ID\"}");
            return;
        }

        WebClient webClient = webClientBuilder.build();

        try {
            ValidationResponse validationResponse = webClient.post()
                    .uri("http://localhost:8083/auth/validate")
                    .header(HttpHeaders.AUTHORIZATION, authHeader)
                    .header("X-Tenant-ID", tenantHeader)
                    .retrieve()
                    .bodyToMono(ValidationResponse.class)
                    .block();

            log.info(" Validation response from multi-auth: {}", validationResponse);

            if (validationResponse != null && validationResponse.active()) {
                List<SimpleGrantedAuthority> authorities = validationResponse.roles().stream()
                        .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                        .collect(Collectors.toList());

                UsernamePasswordAuthenticationToken authenticationToken =
                        new UsernamePasswordAuthenticationToken(
                                validationResponse.username(),
                                null,
                                authorities
                        );

                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                log.info(" Token validated for user: {}", validationResponse.username());
                log.info("✅ Authenticated user: {}", validationResponse.username());
                log.info("🔐 Roles: {}", validationResponse.roles());


                filterChain.doFilter(request, response);
            } else {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                response.getWriter().write("{\"error\":\"Token validation failed\"}");
            }

        } catch (Exception e) {
            log.error(" Exception during token validation", e);
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.getWriter().write("{\"error\":\"Token validation exception\"}");
        }
//       finally {
//          SecurityContextHolder.clearContext();
//        }
    }

    public record ValidationResponse(boolean active, String username, List<String> roles) {
    }
}
