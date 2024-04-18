package com.merteld.jwtconfig.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.merteld.jwtconfig.entity.Agent;
import com.merteld.jwtconfig.repository.AgentRepository;


@Service
public class AgentDetailServiceImpl implements UserDetailsService {

	
    @Autowired
    private AgentRepository userRepository;
    
   @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
       System.out.println("AGENT DETAIL SERVICE IMPL CLASS CONSTRUCOR CALISTI");
    	Agent userEntity = userRepository.findByAgentId(username);
        if (userEntity == null) {
            throw new UsernameNotFoundException("User not found with username: " + username);
        }
        
       
    

   

        return org.springframework.security.core.userdetails.User.builder()
        		.username(userEntity.getAgentId())
        		.password(userEntity.getPassword())
        		.roles(userEntity
        				.getRoleName()
        				.toString())
        				.build();
    }

	
}
