package tn.thinktank.multi.auth.controller;



import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.*;

@RestController
public class OktaController {

   @GetMapping("/okta/secured")
    public String secured(@AuthenticationPrincipal OidcUser user) {
        return "Okta user: " + user.getEmail();
    }

    @GetMapping("/okta/userinfo")
    public Object userInfo(@AuthenticationPrincipal OidcUser user) {
        return user.getClaims();
    }





        //@PreAuthorize("hasRole('custom_role')") // si Okta fournit un rôle
//        @GetMapping("/okta/secured")
//        public String secured() {
//            return "Secured endpoint for Okta with Bearer token!";
//        }
//
//        @GetMapping("/okta/public")
//        public String publicEndpoint() {
//            return "This is a public endpoint.";
//        }

}

