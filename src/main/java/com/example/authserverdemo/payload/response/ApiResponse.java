package com.example.authserverdemo.payload.response;

import lombok.Value;

@Value
public class ApiResponse {

    boolean success;
    String message;
}
