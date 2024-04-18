package com.merteld.jwtconfig.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {

	@PreAuthorize("hasRole('ROLE_ADMIN')")
	@GetMapping("/admin")
	String basic() {
		return "admin";
	}

	// Admin can access both methods if he/she has permission.
	
	@PreAuthorize("hasRole('ROLE_USER')")
	@GetMapping("/user")
	String advanced() {
		return "admin or user";
	}
	
	

}
