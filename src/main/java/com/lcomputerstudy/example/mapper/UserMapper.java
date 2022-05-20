package com.lcomputerstudy.example.mapper;

import java.util.List;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.springframework.security.core.GrantedAuthority;

import com.lcomputerstudy.example.domain.OrderRequest;
import com.lcomputerstudy.example.domain.User;
import com.lcomputerstudy.example.domain.UserInfo;

@Mapper
public interface UserMapper {

	User readUser(String username);

	List<GrantedAuthority> readAuthorities(String username);

	void createUser(User user);

	void createAuthority(User user);

	User getKakaoUserId(String kakaoId);

	int findKakaoId(String kakaoId);

	UserInfo readUser_refresh(String username);

	void deleteUser(String username);

	void deleteAuthority(String username);

	void deleteRoleAdmin(String username);

	List<UserInfo> getUserList();

	void updateAuth(User u);

	void givePoint(@Param("id") String id, @Param("point")String point);

	int getTotal_point(String id);

	void updateBlockUser(String username);

	void updateUnblockUser(String username);

	void updateUserInfo(UserInfo user);

	void deleteWishItem(@Param("code")int code, @Param("username")String username);

	void insertWishItems(OrderRequest item);

	List<OrderRequest> getWishItems(String username);

	void delete_WishItem(int code);

	void updatePoint(@Param("id")String id, @Param("point")int point);

}