package com.deezyWallet.auth_service.controller;

import java.net.URI;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import com.deezyWallet.auth_service.dto.AuthorizationRequestDTO;
import com.deezyWallet.auth_service.dto.UserRegistrationRequestDTO;
import com.deezyWallet.auth_service.entities.AuthErrorCodeEnums;
import com.deezyWallet.auth_service.entities.User;
import com.deezyWallet.auth_service.exceptions.AuthServiceException;
import com.deezyWallet.auth_service.service.IUserService;
import com.deezyWallet.auth_service.utils.JwtUtil;

import jakarta.validation.Valid;

@RestController
@RequestMapping("/auth")
public class AuthController {

	@Autowired
	IUserService userService;
	@Autowired
	private JwtUtil jwtUtil;
	@Autowired
	private PasswordEncoder passwordEncoder;


	@PostMapping("/login")
	public ResponseEntity<String> getAuthToken(@Valid @RequestBody AuthorizationRequestDTO authorizationRequestDTO){
		User user = userService.findUserByUserName(authorizationRequestDTO.username());
		if(passwordEncoder.matches(authorizationRequestDTO.password(), user.getPassword())){
			return ResponseEntity.ok(jwtUtil.generateToken(user.getUsername()));
		}
		throw new AuthServiceException(AuthErrorCodeEnums.INVALID_CREDENTIALS);
	}

	@PostMapping("/register")
	public ResponseEntity<String> registerUser(@Valid @RequestBody UserRegistrationRequestDTO requestDTO){
		User savedUser=userService.registerUser(requestDTO);
		URI location = ServletUriComponentsBuilder
				.fromCurrentRequest()
				.path("/{id}")
				.buildAndExpand(savedUser.getId())
				.toUri();
		return ResponseEntity.created(location).body("User Created Successfully");
	}
	@GetMapping("/ping")
	public ResponseEntity<String> ping(){
		return ResponseEntity.ok("Pong");
	}

}
