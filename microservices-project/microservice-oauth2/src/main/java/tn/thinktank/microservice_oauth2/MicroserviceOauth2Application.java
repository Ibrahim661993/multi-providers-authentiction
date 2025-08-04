package tn.thinktank.microservice_oauth2;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;
import tn.thinktank.microservice_oauth2.entity.User;
import tn.thinktank.microservice_oauth2.repository.UserRepository;
@EnableDiscoveryClient
@SpringBootApplication
public class MicroserviceOauth2Application {

	public static void main(String[] args) {
		SpringApplication.run(MicroserviceOauth2Application.class, args);
	}


	@Bean
	CommandLineRunner init(UserRepository repo, PasswordEncoder encoder) {
		return args -> {
			if (repo.findByUsername("ibrahim").isEmpty()) {
				repo.save(new User(null, "ibrahim", encoder.encode("password"), "USER"));
			}
		};
	}

}
