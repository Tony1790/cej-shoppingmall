package com.lcomputerstudy.example.mapper;

import java.util.HashMap;

import org.apache.ibatis.annotations.Mapper;

import com.lcomputerstudy.example.domain.KakaoUser;

@Mapper
public interface KakaoMapper {

	KakaoUser findKakao(HashMap<String, Object> userInfo);

	void insertKakao(HashMap<String, Object> userInfo);

	void insertAccessToken(HashMap<String, Object> userInfo);

	String getAccessToken(String username);

	void deleteUser(String username);

	
}
