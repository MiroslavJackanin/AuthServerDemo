package com.example.authserverdemo.controller;

import com.example.authserverdemo.payload.response.AuthResponse;
import com.example.authserverdemo.security.jwt.JWTokenKeyProvider;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("public")
public class PublicController {

    private final JWTokenKeyProvider jwTokenKeyProvider;

    public PublicController(JWTokenKeyProvider jwTokenKeyProvider) {
        this.jwTokenKeyProvider = jwTokenKeyProvider;
    }

    @GetMapping("key")
    public ResponseEntity<?> getPublicKey() {

        return ResponseEntity.status(200).body(
                new AuthResponse(jwTokenKeyProvider.getPublicKey().toString(), "PublicKey"));
    }
}
