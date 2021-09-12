package com.example.authserverdemo.payload.response;

import lombok.Value;

@Value
public class AuthResponse {

    String accessToken;
    String tokenType;
}
