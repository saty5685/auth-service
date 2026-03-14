package com.deezyWallet.auth_service.repos;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.deezyWallet.auth_service.entities.User;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

	Optional<User> findByUsername(String name);
	Optional<User> findByUsernameOrEmail(String name, String email);
	Optional<User> findByEmail(String email);

}
