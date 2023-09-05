package com.lcomputerstudy.example.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.lcomputerstudy.example.service.UserService;

@Configuration
@EnableGlobalMethodSecurity(
		prePostEnabled = true,
		securedEnabled = true,
		jsr250Enabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
	
	@Autowired
	private UserService userService;
	
	@Autowired
	private AuthEntryPointJwt unauthorizedHandler;
	
	@Bean
	public AuthTokenFilter authenticationJwtTokenFilter() {
		return new AuthTokenFilter();
	}
	
	@Bean
	@Override
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	@Override
	public void configure(AuthenticationManagerBuilder authenticationManagerBuilder) throws Exception {
		authenticationManagerBuilder.userDetailsService(userService).passwordEncoder(passwordEncoder());
	}
	
	@Override
	protected void configure (HttpSecurity http) throws Exception {
		http.cors().and().csrf().disable()
			//인증 오류 발생 시 사용될 핸들러로 AuthEntryPointJwt 설정.
			.exceptionHandling().authenticationEntryPoint(unauthorizedHandler).and()
			//세션 정책을 STATELESS로 설정하여 서버에서 세션을 유지하지 않는다.
			.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
			//요청에 대한 권한을 구성한다.
			.authorizeRequests().antMatchers("/api/public/**").permitAll()
			.antMatchers("/api/admin/**").hasRole("ADMIN")
			.anyRequest().authenticated();
		
		//기존의 FilterChain전에 AuthTokenFilter authenticationJwtTokenFilter를 실행한다.
		//AuthTokenFilter authenticationJwtTokenFilter는 JWT 인증 절차를 수행하게 된다.
		http.addFilterBefore(authenticationJwtTokenFilter(), UsernamePasswordAuthenticationFilter.class);
	}

}
