package tn.thinktank.resource_service.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class ResourceController {
    @PreAuthorize("hasRole('client_user')")
    @GetMapping("/user")
    public String userAccess() {
        return " User access granted to resource-service!";
    }

    @PreAuthorize("hasRole('client_admin')")
    @GetMapping("/admin")
    public String adminAccess() {
        return " Admin access granted to resource-service!";
    }
}