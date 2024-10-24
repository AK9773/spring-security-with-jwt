package com.ak.config;

import java.io.IOException;
import java.net.URLDecoder;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.ak.model.Users;
import com.ak.repo.UserRepo;
import com.ak.service.JWTService;
import com.ak.service.MyUserDetailsService;

import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class JwtFilter extends OncePerRequestFilter {

	@Autowired
	private JWTService jwtService;

	@Autowired
	private UserRepo repo;

	@Autowired
	MyUserDetailsService myUserDetailsService;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		String token = null;
		String username = null;
//      String authHeader = request.getHeader("Authorization");
//      if (authHeader != null && authHeader.startsWith("Bearer ")) {
//      token = authHeader.substring(7);
//      username = jwtService.extractUserName(token);
//  }

		Cookie[] cookies = request.getCookies();
		if (cookies != null) {
			for (Cookie cookie : cookies) {
				if (cookie.getName().equals("jwt")) {
					// URL decode the JWT token before using it
					token = URLDecoder.decode(cookie.getValue(), "UTF-8");
					try {
						username = jwtService.extractUserName(token);
					} catch (ExpiredJwtException e) {
						// If JWT is expired, log the error and continue the filter chain
						System.out.println("JWT Token is expired");
						filterChain.doFilter(request, response);
						return; // Exit the method to prevent further processing with expired token
					} catch (Exception e) {
						// Log any other exceptions and continue the filter chain
						System.out.println("Invalid JWT Token");
						filterChain.doFilter(request, response);
						return;
					}
				}
			}
		}

		if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
			UserDetails userDetails = myUserDetailsService.loadUserByUsername(username);
			
			if (jwtService.validateToken(token, userDetails)) {
				UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(userDetails,
						null, userDetails.getAuthorities());
				authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
				SecurityContextHolder.getContext().setAuthentication(authToken);
				request.setAttribute("username", userDetails.getUsername());
			}
		}
		filterChain.doFilter(request, response);
	}
}
