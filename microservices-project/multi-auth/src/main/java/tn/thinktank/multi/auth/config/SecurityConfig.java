package tn.thinktank.multi.auth.config;





import tn.thinktank.multi.auth.context.TenantContextHolder;

import tn.thinktank.multi.auth.entity.Tenant;
import tn.thinktank.multi.auth.service.TenantService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthConverter jwtAuthConverter;


    private final TenantService tenantService;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth
                        .anyRequest().authenticated()
                )
                .oauth2ResourceServer(oauth2 -> oauth2
                        .authenticationManagerResolver(authenticationManagerResolver())
                )

                .addFilterBefore(new TenantFilter(), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public AuthenticationManagerResolver<HttpServletRequest> authenticationManagerResolver() {
        return request -> {
            String tenant = TenantContextHolder.getTenant();
            Tenant tenantConfig = tenantService.getTenant(tenant);

            JwtDecoder jwtDecoder = JwtDecoders.fromIssuerLocation(tenantConfig.getIssuerUri());
            JwtAuthenticationProvider provider = new JwtAuthenticationProvider(jwtDecoder);
            provider.setJwtAuthenticationConverter(jwtAuthConverter);
            return new ProviderManager(provider);
        };
    }
}
