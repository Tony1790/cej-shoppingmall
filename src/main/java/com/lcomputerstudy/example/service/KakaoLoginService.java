package com.lcomputerstudy.example.service;

import com.lcomputerstudy.example.domain.KakaoUser;

public interface KakaoLoginService {
	
	public String getAccessToken(String authorize_code);

	public KakaoUser getUserInfo(String access_Token);

	String kakaoUnlink(String code);

}
