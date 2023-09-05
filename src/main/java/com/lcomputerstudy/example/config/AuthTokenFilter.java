package com.lcomputerstudy.example.config;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import com.lcomputerstudy.example.service.UserService;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class AuthTokenFilter extends OncePerRequestFilter {

	private final Logger logger = LoggerFactory.getLogger(this.getClass());
	
	@Autowired
	private JwtUtils jwtUtils;
	
	@Autowired
	private UserService userService;
	
	//HTTP 리퀘스트에서 헤더 추출 후 헤더가 Bearer일 경우 jwt 반환
	private String parseJwt(HttpServletRequest request) {
		String headerAuth = request.getHeader("Authorization");
		
		if(StringUtils.hasText(headerAuth) && headerAuth.startsWith("Bearer ")) {
			return headerAuth.substring(7, headerAuth.length());
		}
		return null;
	}
	
	/*OncePerRequestFilter에서 오버라이드된 메소드.
	 * parseJwt메소드 호출해서 유효성 검사한 후 토큰에서 username 추출.
	 * 추출된 username으로 loadUserByUsername메소드 사용해 User객체를 생성한다.
	*/
	
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		try {
			//parseJwt 메소드 호출
			String jwt = parseJwt(request);
			
			//추출한 토큰의 유효성 검사 후 true일 때, Username 추출
			if(jwt != null && jwtUtils.validateJwtToken(jwt)) {
				String username = jwtUtils.getUserNameFromJwtToken(jwt);
				
				UserDetails userDetials = userService.loadUserByUsername(username);
				
				//UsernamePasswordAuthenticationToken객체를 생성한다. args로 Object principal, Object credentials, Collection<? extends GrantedAuthority를 요구한다.
				//JWT인증에서 password는 필요없기 때문에 userDetails, userDetials.getAuthorities()만 필요하다.
				UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetials, null, userDetials.getAuthorities());
				
				authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
				
				//현재 thread에 authentication을 연결해서 요청처리 중에 현재 인증된 사용자에 대한 정보에 접근이 가능하게 만듬.
				SecurityContextHolder.getContext().setAuthentication(authentication);
			}
		} catch (Exception e) {
			logger.error("Cannot set user authentication: {}", e);
		}
		
		filterChain.doFilter(request, response);
	}

}
