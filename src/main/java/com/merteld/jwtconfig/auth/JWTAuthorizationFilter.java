package com.merteld.jwtconfig.auth;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class JWTAuthorizationFilter extends BasicAuthenticationFilter {

	private final JWTUtil jwtUtil;

	public JWTAuthorizationFilter(AuthenticationManager authManager, JWTUtil jwtUtil) {

		super(authManager);

		this.jwtUtil = jwtUtil;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
			throws IOException, ServletException {

		String header = req.getHeader("Authorization");

		if (header == null || !header.startsWith("Bearer ")) {
			chain.doFilter(req, res);
			return;
		}

		UsernamePasswordAuthenticationToken authentication = getAuthentication(req);

		SecurityContextHolder.getContext().setAuthentication(authentication);
		chain.doFilter(req, res);
	}

	private UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest request) {
		String token = request.getHeader("Authorization");
		if (token != null) {
			try {
				DecodedJWT decodedJWT = JWT.require(Algorithm.HMAC512("EAXCF")).build()
						.verify(token.replace("Bearer ", ""));

				String user = decodedJWT.getSubject();
				String rolesString = decodedJWT.getClaim("roleName").asString();

				List<GrantedAuthority> authorities = Arrays.stream(rolesString.split(", ")).map(role -> {
					if (role.startsWith("ROLE_")) {
						return new SimpleGrantedAuthority(role);
					} else {
						return new SimpleGrantedAuthority("ROLE_" + role.trim());
					}
				}).collect(Collectors.toList());

				if (user != null) {
					return new UsernamePasswordAuthenticationToken(user, null, authorities);
				}
			} catch (Exception e) {
				throw new RuntimeException(e);
			}
		}
		return null;
	}

}
