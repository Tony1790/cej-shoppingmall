package com.lcomputerstudy.example.service;
import java.util.Collection;
import java.util.List;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsService;

import com.lcomputerstudy.example.domain.OrderRequest;
import com.lcomputerstudy.example.domain.User;
import com.lcomputerstudy.example.domain.UserInfo;


public interface UserService extends UserDetailsService {
	
	public User readUser(String username);
	
	Collection<GrantedAuthority> getAuthorities(String username);

	public void createUser(User user);

	public void createAuthority(User user);

	public UserInfo readUser_refresh(String username);

	public void deleteUser(String username);

	public void deleteAuthority(String username);

	public void deleteRoleAdmin(String username);

	public List<UserInfo> getUserList();

	public void updateAuth(User u);

	public void givePoint(String id, String point);

	public int getTotal_point(String id);

	public void updateBlockUser(String username);

	public void updateUnblockUser(String username);

	public void updateUserInfo(UserInfo user);

	public void insertWishItems(OrderRequest item);

	public List<OrderRequest> getWishItems(String username);

	public void delete_WishItem(int code);

	public void updatePoint(String id, int point);
	
}