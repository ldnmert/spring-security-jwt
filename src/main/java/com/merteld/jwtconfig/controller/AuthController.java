package com.merteld.jwtconfig.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.merteld.jwtconfig.entity.Agent;
import com.merteld.jwtconfig.repository.AgentRepository;

@RestController
public class AuthController {

	private final BCryptPasswordEncoder passwordEncoder;
	private final AgentRepository agentRepository;

	@Autowired
	public AuthController(BCryptPasswordEncoder passwordEncoder, AgentRepository agentRepository) {
		this.passwordEncoder = passwordEncoder;
		this.agentRepository = agentRepository;
	}

	@PostMapping("/sign-up")
	public ResponseEntity<String> signUp(@RequestBody Agent agent) {

		System.out.println(agent.getPassword());
		agent.setPassword(passwordEncoder.encode(agent.getPassword()));
		agentRepository.save(agent);
		return new ResponseEntity<>("Kayit olusturuldu.", HttpStatus.CREATED);

	}

}
