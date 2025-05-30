package tn.thinktank.registry_api;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.netflix.eureka.server.EnableEurekaServer;

@EnableEurekaServer
@SpringBootApplication
public class RegistryApiApplication {

	public static void main(String[] args) {
		SpringApplication.run(RegistryApiApplication.class, args);
	}

}
