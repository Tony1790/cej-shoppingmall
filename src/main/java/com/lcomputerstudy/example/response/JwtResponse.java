package com.lcomputerstudy.example.response;

import java.util.List;

import com.lcomputerstudy.example.domain.UserInfo;

public class JwtResponse {

	private String token;
	private List<String> roles;
	private String type = "Bearer";
	private UserInfo user;	
	
	public JwtResponse(String jwt, List<String>u_roles, UserInfo user) {
		this.token = jwt;
		this.roles = u_roles;
		this.user = user;	
	}

	public String getToken() {
		return token;
	}

	public void setToken(String token) {
		this.token = token;
	}

	public List<String> getRoles() {
		return roles;
	}
	
	public UserInfo getUser() {
		return user;
	}

	public void setUser(UserInfo user) {
		this.user = user;
	}

	public void setRoles(List<String> roles) {
		this.roles = roles;
	}

	public String getType() {
		return type;
	}

	public void setType(String type) {
		this.type = type;
	}
	
	
	
}
