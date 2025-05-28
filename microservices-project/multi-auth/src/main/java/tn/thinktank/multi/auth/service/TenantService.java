package tn.thinktank.multi.auth.service;

import tn.thinktank.multi.auth.entity.Tenant;
import tn.thinktank.multi.auth.repository.TenantRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class TenantService {

    private final TenantRepository tenantRepository;

    public Tenant getTenant(String tenantId) {
        return tenantRepository.findByTenantId(tenantId)
                .orElseThrow(() -> new IllegalArgumentException("Tenant not found: " + tenantId));
    }
}
