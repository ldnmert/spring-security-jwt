package com.merteld.jwtconfig.config;

import java.util.Arrays;

import static com.merteld.jwtconfig.security.JWTConstants.LOGIN_URL;
import static com.merteld.jwtconfig.security.JWTConstants.SIGN_UP_URL;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import com.merteld.jwtconfig.security.JWTAuthenticationFilter;
import com.merteld.jwtconfig.security.JWTAuthorizationFilter;
import com.merteld.jwtconfig.security.JWTUtil;
import com.merteld.jwtconfig.service.AgentDetailServiceImpl;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

	private final AgentDetailServiceImpl userService;

	private final BCryptPasswordEncoder bCryptPasswordEncoder;
	private final JWTUtil jwtUtil;

	@Autowired
	public SecurityConfig(AgentDetailServiceImpl userService, BCryptPasswordEncoder bCryptPasswordEncoder,
			JWTUtil jwtUtil) {

		this.userService = userService;

		this.bCryptPasswordEncoder = bCryptPasswordEncoder;
		this.jwtUtil = jwtUtil;
	}

	@Bean
	AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration)
			throws Exception {

		return authenticationConfiguration.getAuthenticationManager();
	}

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {

		AuthenticationManager authenticationManager = authenticationManager(
				httpSecurity.getSharedObject(AuthenticationConfiguration.class));

		httpSecurity.cors(Customizer.withDefaults()).csrf(AbstractHttpConfigurer::disable)
				.authorizeHttpRequests(auth -> auth.requestMatchers(HttpMethod.POST, LOGIN_URL).permitAll()
						.requestMatchers(HttpMethod.POST, SIGN_UP_URL).permitAll()
//						.requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
						.anyRequest().authenticated())
				.addFilter(new JWTAuthenticationFilter(authenticationManager, jwtUtil, userService))
				.addFilter(new JWTAuthorizationFilter(authenticationManager, jwtUtil))
				.sessionManagement(sess -> sess.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

		return httpSecurity.build();
	}

	@Autowired
	void registerProvider(AuthenticationManagerBuilder auth) throws Exception {

		auth.userDetailsService(userService).passwordEncoder(bCryptPasswordEncoder);
	}

	@Bean
	CorsConfigurationSource corsConfigurationSource() {

		CorsConfiguration configuration = new CorsConfiguration();
		configuration.setAllowedOrigins(Arrays.asList("http://localhost:4200"));
		configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE"));
		configuration.setAllowedHeaders(Arrays.asList("*"));
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", configuration);
		return source;
	}

}
