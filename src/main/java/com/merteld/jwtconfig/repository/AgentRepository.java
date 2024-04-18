package com.merteld.jwtconfig.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.merteld.jwtconfig.entity.Agent;

public interface AgentRepository extends JpaRepository<Agent, Long> {

	public Agent findByAgentId(String agentid);
	
	
}