package com.lcomputerstudy.example.service;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.HashMap;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.lcomputerstudy.example.domain.KakaoUser;
import com.lcomputerstudy.example.mapper.KakaoMapper;


@Service
public class KakaoLoginServiceImpl implements KakaoLoginService {
	
	@Autowired
	KakaoMapper kkmapper;

	@Override
	public String getAccessToken(String authorize_code) {
		String access_Token = "";
		String refresh_Token = "";
		String reqURL = "https://kauth.kakao.com/oauth/token";
		
		try {
			URL url = new URL(reqURL);
			
			HttpURLConnection conn = (HttpURLConnection) url.openConnection();
			
			conn.setRequestMethod("POST");
			conn.setDoOutput(true);
			
			BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(conn.getOutputStream()));
			StringBuilder sb = new StringBuilder();
			sb.append("grant_type=authorization_code");
			
			sb.append("&client_id=48b81001e6fa3b0a79971bff9c289b97");
			sb.append("&redirect_uri=http://3.39.35.173:80/auth");
			
			sb.append("&code="+authorize_code);
			bw.write(sb.toString());
			bw.flush();
			
			int responseCode = conn.getResponseCode();
			System.out.println("responseCode : "+responseCode);
			
			BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream()));
			String line = "";
			String result = "";
			
			while ((line = br.readLine()) != null) {
				result += line;
			}
			System.out.println("response body: "+ result);
			
			JsonParser parser = new JsonParser();
			JsonElement element = parser.parse(result);
			
			access_Token = element.getAsJsonObject().get("access_token").getAsString();
			refresh_Token = element.getAsJsonObject().get("refresh_token").getAsString();
			
			System.out.println("access_token : "+ access_Token);
			System.out.println("refresh_Token : "+ refresh_Token);
			
			br.close();
			bw.close();	
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		return access_Token;
	}

	@Override
	public KakaoUser getUserInfo(String access_Token) {
		
		HashMap<String , Object> userInfo = new HashMap<String, Object>();
		String reqURL = "https://kapi.kakao.com/v2/user/me";
		try {
			URL url = new URL(reqURL);
			HttpURLConnection conn = (HttpURLConnection) url.openConnection();
			conn.setRequestMethod("GET");
			
			conn.setRequestProperty("Authorization", "Bearer "+ access_Token);
			
			int responseCode = conn.getResponseCode();
			System.out.println("responseCode : "+ responseCode);
			
			BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream()));
			
			String line = "";
			String result = "";
			
			while((line = br.readLine()) != null) {
				result += line;
			}
			System.out.println("response body : "+ result);
			
			JsonParser parser = new JsonParser();
			JsonElement element = parser.parse(result);
			
			JsonObject properties = element.getAsJsonObject().get("properties").getAsJsonObject();
			JsonObject kakao_account = element.getAsJsonObject().get("kakao_account").getAsJsonObject();
			
			String nickname = properties.getAsJsonObject().get("nickname").getAsString();
			String email = kakao_account.getAsJsonObject().get("email").getAsString();
			
			userInfo.put("nickname", nickname);
			userInfo.put("email", email);
			userInfo.put("access_token", access_Token);
		} catch (IOException e) {
			e.printStackTrace();
		}
	
		KakaoUser user = kkmapper.findKakao(userInfo);
		System.out.println("s: "+ user);
		
		if(user == null && userInfo.get("nickname") != null) {
			kkmapper.insertKakao(userInfo);
			user = kkmapper.findKakao(userInfo);
		} 

		kkmapper.insertAccessToken(userInfo);
		
			return user;

	}

	@Override
	public String kakaoUnlink(String code) {

		String reqURL = "https://kapi.kakao.com/v1/user/unlink";
		
		try {
			URL url = new URL(reqURL);
			
			HttpURLConnection conn = (HttpURLConnection) url.openConnection();
			
			conn.setRequestMethod("POST");
			conn.setRequestProperty("Authorization", "Bearer " + code);
			
			int responseCode = conn.getResponseCode();
			System.out.println("responseCode : "+ responseCode);
			
			BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream()));

			String result = ""; 
			String line = "";
			while ((line = br.readLine()) != null) {
				result += line; 
				} 
			System.out.println(result);

			br.close();	

		}catch (IOException e) {
			e.printStackTrace();
		}

		return "logoutSuccess";
	}
}
