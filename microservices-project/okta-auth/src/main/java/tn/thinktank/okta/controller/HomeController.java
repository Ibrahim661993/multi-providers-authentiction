package tn.thinktank.okta.controller;





import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;


@RestController
@RequestMapping("/api")
public class HomeController {

//    @GetMapping("/")
//    public String home() {
//        return "Bienvenue! Connecte-toi via /secured";
//    }
//    @PreAuthorize("hasRole('client_admin')")
//    @GetMapping("/secured")
//    public String secured(@AuthenticationPrincipal OidcUser oidcUser) {
//        return "Connecté avec Okta : " + oidcUser.getEmail() + " / Nom : " + oidcUser.getFullName();
//    }
//    @PreAuthorize("hasRole('client_user')")
//    @GetMapping("/userinfo")
//    public Object userInfo(@AuthenticationPrincipal OidcUser oidcUser) {
//        return oidcUser.getClaims();  // Toutes les claims : email, name, sub, etc.
//    }

    @PreAuthorize("hasRole('client_user')")
    @GetMapping("/user")
    public String userAccess() {
        return "User access granted to okta-auth!";
    }

    @PreAuthorize("hasRole('client_admin')")
    @GetMapping("/admin")
    public String adminAccess() {
        return "Admin access granted to okta-auth!";
    }
}
