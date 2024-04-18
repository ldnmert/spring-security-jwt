package com.merteld.jwtconfig.security;

import static com.merteld.jwtconfig.security.JWTConstants.TOKEN_PREFIX;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;

import org.json.JSONObject;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.merteld.jwtconfig.entity.Agent;
import com.merteld.jwtconfig.service.AgentDetailServiceImpl;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

	private final AuthenticationManager authenticationManager;
	private final JWTUtil jwtUtil;
	private final AgentDetailServiceImpl userService;

	public JWTAuthenticationFilter(AuthenticationManager authenticationManager, JWTUtil jwtUtil,
			AgentDetailServiceImpl userService) {

		this.authenticationManager = authenticationManager;
		this.jwtUtil = jwtUtil;
		this.userService = userService;

	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest req, HttpServletResponse res)
			throws AuthenticationException {

		try {
			Agent user = new ObjectMapper().readValue(req.getInputStream(), Agent.class);

			return authenticationManager.authenticate(
					new UsernamePasswordAuthenticationToken(user.getAgentId(), user.getPassword(), new ArrayList<>()));
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	protected void successfulAuthentication(HttpServletRequest req, HttpServletResponse res, FilterChain chain,
			Authentication auth) throws IOException, ServletException {
		UserDetails userDetails = userService.loadUserByUsername(
				((org.springframework.security.core.userdetails.User) auth.getPrincipal()).getUsername());

		String token = jwtUtil.generateToken(userDetails);

		JSONObject jsonResponse = new JSONObject();
		jsonResponse.put("token", TOKEN_PREFIX + token);

		PrintWriter writer = res.getWriter();
		writer.write(jsonResponse.toString());
		writer.flush();

	}

}
