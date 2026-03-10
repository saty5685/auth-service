package com.deezyWallet.auth_service.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import com.deezyWallet.auth_service.entities.User;
import com.deezyWallet.auth_service.repos.UserRepository;

@Component
public class CustomUserDetailsService implements UserDetailsService {

	@Autowired
	private UserRepository userRepository;

	@Override
	public UserDetails loadUserByUsername(String username)
			throws UsernameNotFoundException {

		User user = userRepository.findByUsername(username)
				.orElseThrow(() ->
						new UsernameNotFoundException("User not found"));

		return org.springframework.security.core.userdetails.User
				.builder()
				.username(user.getUsername())
				.password(user.getPassword())
				.roles(String.valueOf(user.getRoles())) // ROLE_ prefix auto added
				.build();
	}
}
