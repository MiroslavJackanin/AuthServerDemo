package com.example.authserverdemo.payload.request;

import lombok.Data;

@Data
public class SignInRequest {

    private String email;

    private String password;
}
