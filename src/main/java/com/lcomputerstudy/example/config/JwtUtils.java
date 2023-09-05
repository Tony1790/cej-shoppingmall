package com.lcomputerstudy.example.config;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import javax.xml.bind.DatatypeConverter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import com.lcomputerstudy.example.domain.User;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.UnsupportedJwtException;
import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class JwtUtils {
	
	private static final String jwtSecret = "projectshoppingmall";
	private static final int jwtExpirationMs = 864000;
	private final Logger logger = LoggerFactory.getLogger(this.getClass());
	
	/*Jwt를 생성하는 메소드
	 * 
	 * */
	public String generateJwtToken(Authentication authentication) {
		
		//인증된 사용자에 대해 User객체 생성
		User user = (User)authentication.getPrincipal();
		
		//User객체를 이용해 Jwt생성
		/*인증된 사용자에 대해 JWT를 생성합니다.
		사용자의 이름을 subject로 설정합니다.
		현재 시간을 발행 시간으로 설정합니다.
		JWT의 만료 시간을 설정합니다 (현재 시간 + jwtExpirationMs).
		HS512 알고리즘과 jwtSecret를 사용하여 JWT를 서명합니다.
		생성된 JWT를 반환합니다.*/
		return Jwts.builder()
						.setSubject(user.getUsername())
						.setIssuedAt(new Date())
						.setExpiration(new Date(new Date().getTime() + jwtExpirationMs))
						.signWith(SignatureAlgorithm.HS512, jwtSecret)
						.compact();
	}
	
	//주어진 jwt에서 subject(username)을 추출하는 메소드.
	public String getUserNameFromJwtToken(String token) {
		return Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody().getSubject();
	}
	
	//주어진 jwt에서 Claims를 추출하는 메소드.
	/*	클레임에는 일반적으로 다음과 같은 정보가 포함될 수 있습니다:
	
			iss: 발행자(issuer) - 토큰을 발행한 주체
			sub: 주제(subject) - 토큰의 대상이나 주제 (예: 사용자 ID)
			aud: 수신자(audience) - 토큰의 수신자
			exp: 만료 시간(expiration time) - 토큰의 만료 시간
			nbf: Not Before - 토큰 활성화 시간 (이 시간 이전에는 토큰을 사용할 수 없음)
			iat: 발행 시간(issued at) - 토큰 발행 시간
			jti: JWT ID - 토큰의 고유 식별자*/
	private static Claims getClaimsFormToken(String token) {
		return (Claims) Jwts.parser().setSigningKey(DatatypeConverter.parseBase64Binary(jwtSecret))
				.parseClaimsJws(token).getBody();
	}
	
	//jwt로부터 이메일을 추출하는 메소드.(아마 username이 이메일로 되어있을때를 위한 메소드인듯?)
	public static String getUserEmailFromToken(String token) {
		Claims claims = getClaimsFormToken(token);
		Map<String, Object> map = new HashMap<>(claims);
		String username = (String) map.get("sub");
		
		return username;
	}
	
	//jwt의 유효성을 검사하는 메소드.
	public boolean validateJwtToken(String authToken) {
		try {
			Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(authToken);
			return true;
		} catch (SignatureException e) {
			logger.error("Invalid JWT signature: {}", e.getMessage());
		} catch (MalformedJwtException e) {
			logger.error("Invalid JWT token: {}", e.getMessage());
		} catch (ExpiredJwtException e) {
			logger.error("JWT token is expired: {}", e.getMessage());
		} catch (UnsupportedJwtException e) {
			logger.error("JWT token is unsupported: {}", e.getMessage());
		} catch (IllegalArgumentException e) {
			logger.error("JWT claims string is empty: {}", e.getMessage());
		}
		
		return false;
	}

}
