package com.github.angusyyl.util;

import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.crypto.SecretKey;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;

@Service
public class JwtUtil {
	private static final Logger LOGGER = LoggerFactory.getLogger(JwtUtil.class);

	private int jwtExpiration;
	private int jwtRefreshExpiration;
	private SecretKey accessTokenSecretKey = Keys.secretKeyFor(SignatureAlgorithm.HS512);
	private SecretKey refreshTokenSecretKey = Keys.secretKeyFor(SignatureAlgorithm.HS512);

	@Value("${jwt.expiration}")
	public void setJwtExpiration(int jwtExpiration) {
		this.jwtExpiration = jwtExpiration;
	}

	@Value("${jwt.refresh.expiration}")
	public void setJwtRefreshExpiration(int jwtRefreshExpiration) {
		this.jwtRefreshExpiration = jwtRefreshExpiration;
	}

	// generate token for user
	public String generateToken(UserDetails userDetails, String type) {
		Map<String, Object> claims = new HashMap<>();
		Collection<? extends GrantedAuthority> roles = userDetails.getAuthorities();
		if (roles.contains(new SimpleGrantedAuthority("ROLE_ADMIN"))) {
			claims.put("isAdmin", true);
		}
		if (roles.contains(new SimpleGrantedAuthority("ROLE_USER"))) {
			claims.put("isUser", true);
		}
		if ("access".equals(type)) {
			return doGenerateToken(claims, userDetails.getUsername());
		} else if ("refresh".equals(type)) {
			return doGenerateRefreshToken(claims, userDetails.getUsername());
		} else {
			throw new RuntimeException("Invalid token type.");
		}
	}

	private String doGenerateToken(Map<String, Object> claims, String subject) {
		return Jwts.builder().setClaims(claims).setSubject(subject).setIssuedAt(new Date(System.currentTimeMillis()))
				.setExpiration(new Date(System.currentTimeMillis() + jwtExpiration)).signWith(accessTokenSecretKey)
				.compact();
	}

	private String doGenerateRefreshToken(Map<String, Object> claims, String subject) {
		return Jwts.builder().setClaims(claims).setSubject(subject).setIssuedAt(new Date(System.currentTimeMillis()))
				.setExpiration(new Date(System.currentTimeMillis() + jwtRefreshExpiration))
				.signWith(refreshTokenSecretKey).compact();
	}

	public boolean validateToken(String token) {
		try {
			// Jwt token has not been tampered with
			Jwts.parserBuilder().setSigningKey(accessTokenSecretKey).build().parseClaimsJws(token);
			return true;
		} catch (SignatureException | MalformedJwtException | UnsupportedJwtException | IllegalArgumentException ex) {
			ex.printStackTrace();
			throw new BadCredentialsException("INVALID_CREDENTIALS", ex);
		} catch (ExpiredJwtException ex) {
//			String[] split_string = authToken.split("\\.");
//	        String base64EncodedHeader = split_string[0];
//	        String base64EncodedBody = split_string[1];
//	        String header = new String(Base64.getDecoder().decode(base64EncodedHeader));
//	        String body = new String(Base64.getDecoder().decode(base64EncodedBody));
			throw ex;
//			throw new ExpiredJwtException(claims.getHeader(), claims.getBody(), "Token has Expired", ex);
		}
	}

	public Jws<Claims> validateRefreshToken(String token) {
		try {
			// Jwt token has not been tampered with
			return Jwts.parserBuilder().setSigningKey(refreshTokenSecretKey).build().parseClaimsJws(token);
		} catch (SignatureException | MalformedJwtException | UnsupportedJwtException | IllegalArgumentException ex) {
			throw new BadCredentialsException("INVALID_CREDENTIALS", ex);
		} catch (ExpiredJwtException ex) {
//			String[] split_string = authToken.split("\\.");
//	        String base64EncodedHeader = split_string[0];
//	        String base64EncodedBody = split_string[1];
//	        String header = new String(Base64.getDecoder().decode(base64EncodedHeader));
//	        String body = new String(Base64.getDecoder().decode(base64EncodedBody));
			throw ex;
//			throw new ExpiredJwtException(claims.getHeader(), claims.getBody(), "Token has Expired", ex);
		}
	}

	public String getUsername(String authToken) {
		Jws<Claims> claims = Jwts.parserBuilder().setSigningKey(accessTokenSecretKey).build().parseClaimsJws(authToken);
		return claims.getBody().getSubject();
	}

	public List<SimpleGrantedAuthority> getRolesFromToken(String authToken) {
		List<SimpleGrantedAuthority> roles = null;

		Claims claims = Jwts.parserBuilder().setSigningKey(accessTokenSecretKey).build().parseClaimsJws(authToken)
				.getBody();
		Boolean isAdmin = claims.get("isAdmin", Boolean.class);
		Boolean isUser = claims.get("isUser", Boolean.class);

		if (isAdmin != null && isAdmin == true) {
			roles = Arrays.asList(new SimpleGrantedAuthority("ROLE_ADMIN"));
		}
		if (isUser != null && isUser == true) {
			roles = Arrays.asList(new SimpleGrantedAuthority("ROLE_USER"));
		}
		return roles;
	}
}
