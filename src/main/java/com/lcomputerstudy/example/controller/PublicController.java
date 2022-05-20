package com.lcomputerstudy.example.controller;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.StringUtils;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.lcomputerstudy.example.config.JwtUtils;
import com.lcomputerstudy.example.domain.Category;
import com.lcomputerstudy.example.domain.KakaoUser;
import com.lcomputerstudy.example.domain.Option;
import com.lcomputerstudy.example.domain.OrderRequest;
import com.lcomputerstudy.example.domain.Product;
import com.lcomputerstudy.example.domain.QABoard;
import com.lcomputerstudy.example.domain.Review;
import com.lcomputerstudy.example.domain.User;
import com.lcomputerstudy.example.domain.UserInfo;
import com.lcomputerstudy.example.mapper.KakaoMapper;
import com.lcomputerstudy.example.request.JoinRequest;
import com.lcomputerstudy.example.request.LoginRequest;
import com.lcomputerstudy.example.response.JwtResponse;
import com.lcomputerstudy.example.service.BoardService;
import com.lcomputerstudy.example.service.CategoryService;
import com.lcomputerstudy.example.service.KakaoLoginService;
import com.lcomputerstudy.example.service.ProductService;
import com.lcomputerstudy.example.service.UserService;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/public")
public class PublicController {
	
	private final Logger logger = LoggerFactory.getLogger(this.getClass());
	
	@Value("${shoppingmall.key}")
	private String key;
	
	@Autowired
	AuthenticationManager authenticationManager;
	
	@Autowired
	PasswordEncoder encoder;
	
	@Autowired
	JwtUtils jwtUtils;
	
	@Autowired
	UserService userservice;
	
	@Autowired
	KakaoMapper kkmapper;
	
	@Autowired
	private KakaoLoginService ks;
	
	@Autowired
	CategoryService categoryService;
	
	@Autowired
	ProductService productService;
	
	@Autowired
	BoardService boardService;
	
	@PostMapping("newUser")
	public ResponseEntity<?> insertNewUser(@Validated @RequestBody JoinRequest joinUser) {
		
		String encodedPassword = new BCryptPasswordEncoder().encode(joinUser.getPassword());
		
		User user = new User();
		user.setUsername(joinUser.getUsername());
		user.setName(joinUser.getName());
		user.setPassword(encodedPassword);
		user.setIsAccountNonExpired(true);
		user.setIsAccountNonLocked(true);
		user.setIsCredentialsNonExpired(true);
		user.setIsEnabled(true);
		user.setAuthorities(AuthorityUtils.createAuthorityList("ROLE_USER"));
		user.setAuth("USER");
		user.setPhone(joinUser.getPhone());
		user.setAddress(joinUser.getAddress());
	
		userservice.createUser(user);
		userservice.createAuthority(user);
		
		return new ResponseEntity<>("success", HttpStatus.OK);
		
	}
	
	@PostMapping("login")
	public ResponseEntity<?> loginUser(@Validated @RequestBody LoginRequest loginUser) {
		
		logger.info("test" + loginUser);
		
		Authentication authentication = authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(loginUser.getUsername(), loginUser.getPassword()));
		
		SecurityContextHolder.getContext().setAuthentication(authentication);
		String jwt = jwtUtils.generateJwtToken(authentication);
		
		User user = (User) authentication.getPrincipal();
		logger.info("dddd"+ authentication.getPrincipal());
		
		List<String> roles = user.getAuthorities().stream()
				.map(item -> item.getAuthority())
				.collect(Collectors.toList());
		UserInfo userInfo = userservice.readUser_refresh(user.getUsername());
		List<OrderRequest> wishItems = userservice.getWishItems(user.getUsername());
		for(OrderRequest item : wishItems) {
			Product p = productService.getProductDetails(item.getCode());
			item.setProduct(p);
		}
		userInfo.setWishItems(wishItems);
				
		return ResponseEntity.ok(new JwtResponse(jwt, roles, userInfo));
	}
	
	@GetMapping("/kakaologin")
	public ResponseEntity<?> kakaoLogin(@RequestParam(value = "code", required = false) String code) throws Exception {
		System.out.println("#####"+code);
		
		String access_token = ks.getAccessToken(code);
		KakaoUser kuser = ks.getUserInfo(access_token);
	
		User user = userservice.readUser(kuser.getK_email());
		
		if(user == null) {
			
			System.out.println(key);
			String encodedPassword = new BCryptPasswordEncoder().encode(key);

			User newUser = new User();
			newUser.setUsername(kuser.getK_email());
			newUser.setName(kuser.getK_name());
			newUser.setPassword(encodedPassword);
			newUser.setIsAccountNonExpired(true);
			newUser.setIsAccountNonLocked(true);
			newUser.setIsCredentialsNonExpired(true);
			newUser.setIsEnabled(true);
			newUser.setAuthorities(AuthorityUtils.createAuthorityList("ROLE_USER"));
			newUser.setOauth("kakao");
			newUser.setAuth("USER");
			
			userservice.createUser(newUser);
			userservice.createAuthority(newUser);
			
			user = userservice.readUser(kuser.getK_email());
		}

		Authentication authentication = authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(user.getUsername(), key ));
		
		SecurityContextHolder.getContext().setAuthentication(authentication);
		String jwt = jwtUtils.generateJwtToken(authentication);
		
		User principal = (User) authentication.getPrincipal();
		
		List<String> roles = principal.getAuthorities().stream()
				.map(item -> item.getAuthority())
				.collect(Collectors.toList());

		UserInfo userInfo = userservice.readUser_refresh(user.getUsername());
		List<OrderRequest> wishItems = userservice.getWishItems(user.getUsername());
		for(OrderRequest item : wishItems) {
			Product p = productService.getProductDetails(item.getCode());
			item.setProduct(p);
		}
		userInfo.setWishItems(wishItems);
		
		return ResponseEntity.ok(new JwtResponse(jwt, roles, userInfo));
	}
	
	@GetMapping("/kakaoUnlink")
	public ResponseEntity<?> kakaoUnlink(HttpServletRequest request) throws Exception {
		
		String token = new String();
		token = request.getHeader("Authorization");

		if(StringUtils.hasText(token) && token.startsWith("Bearer ")) {
			token = token.substring(7, token.length());
		}
		
		String username = jwtUtils.getUserEmailFromToken(token);
		System.out.println("id = "+username);
		
		String access_token = kkmapper.getAccessToken(username);
		
		String result = ks.kakaoUnlink(access_token);
		
		kkmapper.deleteUser(username);
		userservice.deleteUser(username);
		userservice.deleteAuthority(username);
		
		return new ResponseEntity<>(result, HttpStatus.OK);
	}
	
	@GetMapping("/unpackToken")
	public ResponseEntity<?> unpackToken(HttpServletRequest request) {
		String token = new String();
		token = request.getHeader("Authorization");

		if(StringUtils.hasText(token) && token.startsWith("Bearer ")) {
			token = token.substring(7, token.length());
		}
		
		String username = jwtUtils.getUserEmailFromToken(token);
		UserInfo user = userservice.readUser_refresh(username);
		
		List<String> roles = userservice.getAuthorities(username).stream()
				.map(item -> item.getAuthority()).collect(Collectors.toList());
		
		List<OrderRequest> wishItems = userservice.getWishItems(username);
		for(OrderRequest item : wishItems) {
			Product p = productService.getProductDetails(item.getCode());
			item.setProduct(p);
		}
		user.setWishItems(wishItems);
		
		return ResponseEntity.ok(new JwtResponse(token, roles, user));
	}
	
	@PostMapping("/roleAdmin")
	public ResponseEntity<?> addRoleAdmin(HttpServletRequest request, @Validated @RequestBody UserInfo user_) {
		String token = new String();
		token = request.getHeader("Authorization");

		if(StringUtils.hasText(token) && token.startsWith("Bearer ")) {
			token = token.substring(7, token.length());
		}
		
		User u = userservice.readUser(user_.getUsername());
		
		u.setAuthorities(AuthorityUtils.createAuthorityList("ROLE_USER", "ROLE_ADMIN"));
		userservice.createAuthority(u);
		u.setAuth("ADMIN");
		userservice.updateAuth(u);
		
		List<String> roles = userservice.getAuthorities(u.getUsername()).stream()
								.map(item -> item.getAuthority())
								.collect(Collectors.toList());
		
		UserInfo user = userservice.readUser_refresh(user_.getUsername());
		List<OrderRequest> wishItems = userservice.getWishItems(user.getUsername());
		for(OrderRequest item : wishItems) {
			Product p = productService.getProductDetails(item.getCode());
			item.setProduct(p);
		}
		user.setWishItems(wishItems);
		
		return ResponseEntity.ok(new JwtResponse(token, roles, user));
	}
	
	@DeleteMapping("/roleAdmin")
	public ResponseEntity<?> deleteRoleAdmin(HttpServletRequest request, @Validated UserInfo user_) {
		String token = new String();
		token = request.getHeader("Authorization");

		if(StringUtils.hasText(token) && token.startsWith("Bearer ")) {
			token = token.substring(7, token.length());
		}
		
		User u = userservice.readUser(user_.getUsername());
		
		u.setAuthorities(AuthorityUtils.createAuthorityList("ROLE_USER"));
		userservice.deleteRoleAdmin(u.getUsername());
		u.setAuth("USER");
		userservice.updateAuth(u);
		
		List<String> roles= userservice.getAuthorities(u.getUsername()).stream()
				.map(item -> item.getAuthority())
				.collect(Collectors.toList());
		
		UserInfo user = userservice.readUser_refresh(user_.getUsername());
		List<OrderRequest> wishItems = userservice.getWishItems(user.getUsername());
		for(OrderRequest item : wishItems) {
			Product p = productService.getProductDetails(item.getCode());
			item.setProduct(p);
		}
		user.setWishItems(wishItems);
		
		return ResponseEntity.ok(new JwtResponse(token, roles, user));
	}
	
	@PutMapping("user")
	public ResponseEntity<?> updateUserInfo(@Validated @RequestBody UserInfo user) {
	
		userservice.updateUserInfo(user);
		
		return new ResponseEntity<>(HttpStatus.OK);
	}
	
	@DeleteMapping("user")
	public ResponseEntity<?> deleteUser(@Validated String username) {
		
		userservice.deleteUser(username);
		userservice.deleteAuthority(username);
		
		return new ResponseEntity<>(HttpStatus.OK);
	}
	
	@GetMapping("menu")
	public ResponseEntity<?> getShopMainPage_menu() {
		
		List<Category> list = categoryService.getMenu();
		
		return new ResponseEntity<>(list, HttpStatus.OK);
	}
	
	@GetMapping("productlist-shop")
	public ResponseEntity<?> getProductList_shop(@Validated  int code) {
		
		List<Integer> codes = categoryService.getCodes(code);
		List<Product> list = new ArrayList<>();

		for(int code_ : codes) {
			List<Product> p = productService.getproductlist_shop(code_);
			list.addAll(p);
		}
		
		
		return new ResponseEntity<>(list, HttpStatus.OK);
	}
	
	@GetMapping("product-details-shop")
	public ResponseEntity<?> getProductDetails_shop(@Validated int code) {
		
		Product product = productService.getProductDetails(code);
		
		String t = product.getType_s();
		if(t.contains(",")) {
			product.setType(Arrays.asList(t.split(",")));
		}else {
			product.setType(Arrays.asList(t));
		}

		String files = product.getFilesname();
		if(files.contains(",")) {
			product.setFile_list(Arrays.asList(files.split(",")));
		}else {
			product.setFile_list(Arrays.asList(files));
		}

		List<Option> options = productService.getOptions(code);
		product.setOptions(options);
		
		List<String> options_s = new ArrayList<String>();
		for(Option option : options) {
			options_s.add(option.getOption());
		}
		
		product.setOptions_s(options_s);
		
		return new ResponseEntity<>(product, HttpStatus.OK);
	}
	
	@GetMapping("qa-post")
	public ResponseEntity<?> getQABoardList() {
		
		List<QABoard> list = boardService.getQABoardList();
		
		return new ResponseEntity<>(list, HttpStatus.OK);
	}
	
	@GetMapping("qa-post-details")
	public ResponseEntity<?> getQAPostDetails(@Validated int num) {
		
		boardService.addHit(num);
		QABoard post = boardService.getQAPostDetails(num);
		
		return new ResponseEntity<>(post, HttpStatus.OK);
	}
	
	@GetMapping("review")
	public ResponseEntity<?> getReviews(@Validated int code) {
		
		List<Review> list = boardService.getReviews(code);
		
		return new ResponseEntity<>(list, HttpStatus.OK);
	}
	
	@PostMapping("heart-items")
	public ResponseEntity<?> getHeartImems(@Validated @RequestBody List<Integer> list){
		
		List<Product> items = new ArrayList<Product>();
		for(int item : list) {
			Product p = productService.getProductDetails(item);
			items.add(p);
		}
		
		return new ResponseEntity<>(items, HttpStatus.OK);
	}
	
}