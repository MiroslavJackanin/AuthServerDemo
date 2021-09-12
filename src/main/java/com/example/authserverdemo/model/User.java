package com.example.authserverdemo.model;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.util.List;

@Document(collection = "users")
@Getter @Setter @NoArgsConstructor
public class User {

    @Id
    private String id;

    private String name;

    private String email;

    private String imageUrl;

    private Boolean emailVerified = false;

    private String password;

    private AuthProvider provider;

    private String providerId;

    private List<Role> roles;
}
