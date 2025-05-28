package tn.thinktank.okta.controller;





import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;


@RestController
public class HomeController {

    @GetMapping("/")
    public String home() {
        return "Bienvenue! Connecte-toi via /secured";
    }

    @GetMapping("/secured")
    public String secured(@AuthenticationPrincipal OidcUser oidcUser) {
        return "Connecté avec Okta : " + oidcUser.getEmail() + " / Nom : " + oidcUser.getFullName();
    }

    @GetMapping("/userinfo")
    public Object userInfo(@AuthenticationPrincipal OidcUser oidcUser) {
        return oidcUser.getClaims();  // Toutes les claims : email, name, sub, etc.
    }
}
