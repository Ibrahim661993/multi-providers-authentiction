package tn.thinktank.auth_api;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;

@EnableDiscoveryClient
@SpringBootApplication
public class KeycloakAuthApplication {

	public static void main(String[] args) {
		SpringApplication.run(KeycloakAuthApplication.class, args);
	}

}
