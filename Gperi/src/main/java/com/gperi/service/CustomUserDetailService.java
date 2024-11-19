package com.gperi.service;

import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.gperi.model.CustomUserDetail;
import com.gperi.model.User;
import com.gperi.repository.UserRepository;


@Service
public class CustomUserDetailService implements UserDetailsService {

	@Autowired
	UserRepository userRepository;
	@Override
	public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
		
		Optional<User> user = userRepository.findUserByEmail(email);//Custom exception jasto xD
		user.orElseThrow(() -> new UsernameNotFoundException("User not found :)")); //user xaina vane exception throw gare wala
		return user.map(CustomUserDetail::new).get();
		
	}
}
