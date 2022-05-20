package com.lcomputerstudy.example.service;

import java.util.Collection;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.lcomputerstudy.example.domain.OrderRequest;
import com.lcomputerstudy.example.domain.User;
import com.lcomputerstudy.example.domain.UserInfo;
import com.lcomputerstudy.example.mapper.UserMapper;

@Service
public class UserServiceImpl implements UserService {
	
	@Autowired
	UserMapper usermapper;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		
		User user = usermapper.readUser(username);
		user.setAuthorities(getAuthorities(username));
		return user;
		
	}


	@Override
	public Collection<GrantedAuthority> getAuthorities(String username) {
		
		List<GrantedAuthority> authorities = usermapper.readAuthorities(username);
		return authorities;
	}


	@Override
	public User readUser(String username) {
		// TODO Auto-generated method stub
		return usermapper.readUser(username);
	}


	@Override
	public void createUser(User user) {
		usermapper.createUser(user);
		
	}


	@Override
	public void createAuthority(User user) {
		usermapper.createAuthority(user);
		
	}


	@Override
	public UserInfo readUser_refresh(String username) {
		// TODO Auto-generated method stub
		return usermapper.readUser_refresh(username);
	}


	@Override
	public void deleteUser(String username) {
		usermapper.deleteUser(username);
		
	}


	@Override
	public void deleteAuthority(String username) {
		usermapper.deleteAuthority(username);
		
	}


	@Override
	public void deleteRoleAdmin(String username) {
		usermapper.deleteRoleAdmin(username);
		
	}


	@Override
	public List<UserInfo> getUserList() {
		// TODO Auto-generated method stub
		return usermapper.getUserList();
	}


	@Override
	public void updateAuth(User u) {
		usermapper.updateAuth(u);
		
	}


	@Override
	public void givePoint(String id, String point) {
		usermapper.givePoint(id, point);
		
	}


	@Override
	public int getTotal_point(String id) {
		// TODO Auto-generated method stub
		return usermapper.getTotal_point(id);
	}


	@Override
	public void updateBlockUser(String username) {
		usermapper.updateBlockUser(username);
	}


	@Override
	public void updateUnblockUser(String username) {
		usermapper.updateUnblockUser(username);
		
	}


	@Override
	public void updateUserInfo(UserInfo user) {
		usermapper.updateUserInfo(user);
		
	}
	

	@Override
	public void insertWishItems(OrderRequest item) {
		usermapper.insertWishItems(item);
		
	}


	@Override
	public List<OrderRequest> getWishItems(String username) {
		
		return usermapper.getWishItems(username);
		
	}


	@Override
	public void delete_WishItem(int code) {
		usermapper.delete_WishItem(code);
		
	}


	@Override
	public void updatePoint(String id, int point) {
		usermapper.updatePoint(id, point);
		
	}

}