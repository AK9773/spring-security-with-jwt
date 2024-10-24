package com.ak.controller;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.function.EntityResponse;

import com.ak.model.Users;
import com.ak.service.UserService;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;

@RestController
@RequestMapping("/user-api")
public class UserController {

	@Autowired
	private UserService service;

	@PostMapping("/register")
	public Users register(@RequestBody Users user) {
		return service.register(user);

	}

	@PostMapping("/login")
	public String login(@RequestBody Users user, HttpServletResponse response) throws UnsupportedEncodingException {

		String token = service.verify(user);
		String encodedJwtToken = URLEncoder.encode(token, "UTF-8");
		Cookie jwtCookie = new Cookie("jwt", encodedJwtToken);
		jwtCookie.setHttpOnly(true); // More secure, prevents JS access
		jwtCookie.setSecure(true);
		jwtCookie.setMaxAge(3600); // 1 hour expiry time
		jwtCookie.setPath("/"); // Cookie path

		// Add cookie to the response
		response.addCookie(jwtCookie);
		return "Login successful";
	}

	@PostMapping("/logout")
	public ResponseEntity<String> removeCookie(HttpServletResponse response) {

		Cookie jwtCookie = new Cookie("jwt", null);
		jwtCookie.setHttpOnly(true);
		jwtCookie.setMaxAge(0); // Set max age to 0 to delete the cookie
		jwtCookie.setPath("/"); // Set the same path to ensure the cookie is removed

		// Add the cookie to the response, which will remove it from the browser
		response.addCookie(jwtCookie);
		return new ResponseEntity<String>("Logout Successful", HttpStatus.OK);
	}
}