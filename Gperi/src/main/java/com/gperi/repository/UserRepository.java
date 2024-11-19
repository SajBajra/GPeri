package com.gperi.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.gperi.model.User;



public interface UserRepository extends JpaRepository<User, Integer> {
	
	
	User findByEmail(String email);
	boolean existsByEmail(String email);
	boolean existsByEmailAndPassword(String username, String password);
	Optional<User>findUserByEmail(String email);
}
