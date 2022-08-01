package com.github.angusyyl.controller;

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
import com.github.angusyyl.dto.AppUser;
import com.github.angusyyl.util.JwtUtil;

@RestController
@RequestMapping("/api")
public class Controller {

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
		String token = jwtTokenUtil.generateToken(userDetails);
		return ResponseEntity.ok(new AuthResponse(token));
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
