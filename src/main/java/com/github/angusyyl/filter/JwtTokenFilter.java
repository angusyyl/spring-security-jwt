package com.github.angusyyl.filter;

import java.io.IOException;
import java.util.List;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import com.github.angusyyl.repository.IUserRepo;
import com.github.angusyyl.util.JwtUtil;

import io.jsonwebtoken.ExpiredJwtException;

@Component
public class JwtTokenFilter extends OncePerRequestFilter {

	@Autowired
	private IUserRepo userRepo;

	private final JwtUtil jwtTokenUtil;

	public JwtTokenFilter(JwtUtil jwtTokenUtil) {
		this.jwtTokenUtil = jwtTokenUtil;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws ServletException, IOException {

		try {
			// Get authorization header and validate
			final String header = request.getHeader(HttpHeaders.AUTHORIZATION);
			if (!StringUtils.hasText(header) || !header.startsWith("Bearer ")) {
				chain.doFilter(request, response);
				return;
			}

			// Get jwt token and validate
			final String token = header.split(" ")[1].trim();
			if (!jwtTokenUtil.validateToken(token)) {
				chain.doFilter(request, response);
				return;
			}

			// Get user identity and set it on the spring security context
			UserDetails userDetails = userRepo.findByUsername(jwtTokenUtil.getUsername(token));

			UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails,
					null, userDetails == null ? List.of() : userDetails.getAuthorities());

			authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

			SecurityContextHolder.getContext().setAuthentication(authentication);
			System.out.println(
					"authenticated name is " + SecurityContextHolder.getContext().getAuthentication().getName());
		} catch (ExpiredJwtException ex) {
			request.setAttribute("exception", ex);
			throw ex;
		} catch (BadCredentialsException ex) {
			request.setAttribute("exception", ex);
			throw ex;
		}
		chain.doFilter(request, response);
	}

}
