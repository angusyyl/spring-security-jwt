package com.github.angusyyl.controller;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.github.angusyyl.AuthRequest;
import com.github.angusyyl.AuthResponse;
import com.github.angusyyl.CustomUserDetailsService;
import com.github.angusyyl.RefreshTokenReq;
import com.github.angusyyl.dto.AppUser;
import com.github.angusyyl.util.JwtUtil;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;

@RestController
@RequestMapping("/api")
public class Controller {
	private static final Logger LOGGER = LoggerFactory.getLogger(Controller.class);

	// this should be stored in safe places, e.g. Redis
	private List<String> refreshTokens = new ArrayList<String>();
	
	@Autowired
	private AuthenticationManager authenticationManager;

	@Autowired
	private CustomUserDetailsService userDetailsService;

	@Autowired
	private JwtUtil jwtTokenUtil;

	@PostMapping(value = "/public/login", consumes = MediaType.APPLICATION_JSON_VALUE)
	public ResponseEntity<?> login(@RequestBody AuthRequest req) {
		String loginUsername = req.getUsername();
		String loginPwd = req.getPassword();

		try {
			Authentication auth = authenticationManager
					.authenticate(new UsernamePasswordAuthenticationToken(loginUsername, loginPwd));
		} catch (AuthenticationException authEx) {
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(authEx.getMessage());
		}
		UserDetails userDetails = userDetailsService.loadUserByUsername(loginUsername);
		String accessToken = jwtTokenUtil.generateToken(userDetails, "access");
		String refreshToken = jwtTokenUtil.generateToken(userDetails, "refresh");
		this.refreshTokens.add(refreshToken);
		LOGGER.info("Stored refreshtokens: {}", this.refreshTokens.toString());
		return ResponseEntity.ok(new AuthResponse(accessToken, refreshToken));
	}

	@PostMapping(value = "/public/refreshtoken", consumes = MediaType.APPLICATION_JSON_VALUE)
	public ResponseEntity<?> refreshToken(@RequestBody RefreshTokenReq refreshTokenReq) {
		String refreshToken = refreshTokenReq.getRefreshToken();
		if ("".equals(refreshToken)) {
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Refresh token is empty.");
		} else {
			LOGGER.info("refreshToken: {}", refreshToken);
			if (!refreshTokens.contains(refreshToken)) {
				return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Invalid refresh token.");
			} else {
				try {
					LOGGER.info("Validating refresh token.");
					Jws<Claims> claims = jwtTokenUtil.validateRefreshToken(refreshToken);
					UserDetails userDetails = userDetailsService.loadUserByUsername(claims.getBody().getSubject());
					String accessToken = jwtTokenUtil.generateToken(userDetails, "access");
					LOGGER.info("New access token generated.");
					
					// rotate refresh token
					this.refreshTokens = this.refreshTokens.stream().filter(token -> !token.equals(refreshToken)).collect(Collectors.toList());
					String newRefreshToken = jwtTokenUtil.generateToken(userDetails, "refresh");
					this.refreshTokens.add(newRefreshToken);
					LOGGER.info("Rotate refresh token.");
					return ResponseEntity.ok(new AuthResponse(accessToken, newRefreshToken));
				} catch (SignatureException | MalformedJwtException | UnsupportedJwtException | IllegalArgumentException | ExpiredJwtException ex) {
					return ResponseEntity.status(HttpStatus.FORBIDDEN).body(ex.getMessage());
				}
			}
		}
	}

	/**
	 * Endpoints accessible by anyone, including the unauthenticated.
	 * 
	 * @return
	 */
	@PostMapping(value = "/public/users", consumes = MediaType.APPLICATION_JSON_VALUE)
	public String registerUser(@RequestBody AppUser user) {
		return "Registered user " + user.getUsername();
	}

	/**
	 * Endpoints accessible by anyone, including the unauthenticated.
	 * 
	 * @return
	 */
	@GetMapping("/public/conn-test")
	public String connectivityTest() {
		return "Your access to the website is successful. But authentication is required for some operations.";
	}

	/**
	 * Endpoints accessible by ADMIN roles only.
	 * 
	 * @return
	 */
	@GetMapping("/admin/users")
	public String getAllUsers() {
		return "List all users.";
	}

	/**
	 * Endpoints accessible by ADMIN roles only.
	 * 
	 * @return
	 */
	@GetMapping("/admin/stats")
	public String getSystemStats() {
		return "Report statistics info of the system.";
	}

	/**
	 * Endpoints accessible by ADMIN and USER roles.
	 * 
	 * @return
	 */
	@GetMapping("/private/search")
	public String search() {
		return "User performs a search operation.";
	}
}
