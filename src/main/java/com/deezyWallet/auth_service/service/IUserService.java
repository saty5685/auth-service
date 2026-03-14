package com.deezyWallet.auth_service.service;

import com.deezyWallet.auth_service.dto.UserRegistrationRequestDTO;
import com.deezyWallet.auth_service.entities.User;

public interface IUserService {
	public Boolean userExists(String usename, String email);
	public User findUserByUserName(String usename);
	public User registerUser(UserRegistrationRequestDTO requestDTO);
	public void validateRequest(UserRegistrationRequestDTO requestDTO);
}
