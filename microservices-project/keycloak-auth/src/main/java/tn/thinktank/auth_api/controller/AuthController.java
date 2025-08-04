package tn.thinktank.auth_api.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import tn.thinktank.auth_api.model.User;
import tn.thinktank.auth_api.service.AuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

@RestController
@RequestMapping("/auth")
public class AuthController {
    @Autowired
    private AuthService authService;

    @PostMapping("register")
    public User registerUser(@RequestBody User user) {
        return authService.saveUser(user);
    }

    @GetMapping("/user/{username}")
    public Optional<User> getUser(@PathVariable String username) {
        return authService.getUserByUsername(username);
    }


    @PreAuthorize("hasRole('client_user')")
    @GetMapping
    public String hello() {
        return "Hello from Spring Boot & keycloak!";
    }

    @PreAuthorize("hasRole(('client_admin'))")
    @GetMapping("/hello-2")
    public String hello2() {
        return "Hello from Spring Boot & keycloak!-ADMIN";
    }
}
