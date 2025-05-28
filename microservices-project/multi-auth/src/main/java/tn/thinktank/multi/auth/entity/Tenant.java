package tn.thinktank.multi.auth.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.*;

@Entity
@Table(name = "tenants")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Tenant {

    @Id
    private String tenantId; // ex: tenant-okta, tenant-keycloak

    @Column(nullable = false)
    private String issuerUri;

    @Column(nullable = false)
    private String clientId;

    @Column(nullable = false)
    private String clientSecret;
}
