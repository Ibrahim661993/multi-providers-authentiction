package tn.thinktank.microservice_oauth2.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import tn.thinktank.microservice_oauth2.entity.User;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);
}
