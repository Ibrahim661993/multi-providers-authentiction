package tn.thinktank.multi.auth.repository;

import tn.thinktank.multi.auth.entity.Tenant;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface TenantRepository extends JpaRepository<Tenant, String> {
    Optional<Tenant> findByTenantId(String tenantId);
}
