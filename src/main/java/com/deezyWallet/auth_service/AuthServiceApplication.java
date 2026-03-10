package com.deezyWallet.auth_service;

import org.apache.catalina.startup.Tomcat;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import com.deezyWallet.auth_service.entities.AuthErrorCodeEnums;

@SpringBootApplication
public class AuthServiceApplication {
	private static Logger logger=LoggerFactory.getLogger(AuthServiceApplication.class);

	public static void main(String[] args) {
		validateErrorCodeEnum();
		SpringApplication.run(AuthServiceApplication.class, args);
		Tomcat tomcat=new Tomcat();
	}

	private static void validateErrorCodeEnum() {
		logger.info("Validating " + AuthErrorCodeEnums.class.getName());
		AuthErrorCodeEnums.validateErrorCodes();
		logger.info("Validating done for " + AuthErrorCodeEnums.class.getName());
	}

}
