package com.deezyWallet.auth_service.service;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.deezyWallet.auth_service.dto.UserRegistrationRequestDTO;
import com.deezyWallet.auth_service.entities.AuthErrorCodeEnums;
import com.deezyWallet.auth_service.entities.Role;
import com.deezyWallet.auth_service.entities.User;
import com.deezyWallet.auth_service.exceptions.AuthServiceException;
import com.deezyWallet.auth_service.repos.UserRepository;

@Service
public class UserServiceImpl implements IUserService{
	@Autowired
	UserRepository userRepository;

	@Autowired
	private PasswordEncoder passwordEncoder;

	@Override
	public Boolean userExists(String username){
		return userRepository.findByUsername(username).isPresent();
	}

	@Override
	public User findUserByUserName(String username) {
		return userRepository.findByUsername(username).orElseThrow(() -> new AuthServiceException(AuthErrorCodeEnums.USER_NOT_FOUND));
	}

	@Override
	public User registerUser(UserRegistrationRequestDTO requestDTO) {
		Set<Role> roles=requestDTO.roles();
		if(requestDTO.roles()==null || requestDTO.roles().isEmpty()){
			roles=new HashSet<>(List.of(Role.USER));
		}
		User user =new User(requestDTO.username(), requestDTO.email(), passwordEncoder.encode(requestDTO.password()),
				roles);
		return userRepository.save(user);
	}
}
