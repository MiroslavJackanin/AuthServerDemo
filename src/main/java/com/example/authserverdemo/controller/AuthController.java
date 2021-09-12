package com.example.authserverdemo.controller;

import com.example.authserverdemo.payload.request.SignInRequest;
import com.example.authserverdemo.payload.request.SignUpRequest;
import com.example.authserverdemo.payload.response.ApiResponse;
import com.example.authserverdemo.payload.response.AuthResponse;
import com.example.authserverdemo.security.service.UserServiceImpl;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.naming.AuthenticationException;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final UserServiceImpl userService;

    public AuthController(UserServiceImpl userService) {
        this.userService = userService;
    }

    @PostMapping("/signIn")
    public ResponseEntity<?> authenticateUser(@RequestBody SignInRequest signInRequest) {

        String token = userService.authenticateUser(signInRequest);
        return ResponseEntity.status(200).body(new AuthResponse(token, "Bearer"));
    }

    @PostMapping("/signUp")
    public ResponseEntity<?> registerUser(@RequestBody SignUpRequest signUpRequest) {

        try {
            userService.registerNewUser(signUpRequest);
        } catch (AuthenticationException e) {
            return ResponseEntity.status(500).body(new ApiResponse(false, e.getMessage()));
        }
        return ResponseEntity.status(200).body(new ApiResponse(true, "User registered successfully!"));
    }
}
