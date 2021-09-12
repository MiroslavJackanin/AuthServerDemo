package com.example.authserverdemo.model;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

@Document(collection = "roles")
@Getter @Setter @NoArgsConstructor
public class Role {

    public static final String ROLE_USER = "ROLE_USER";
    public static final String ROLE_ADMIN = "ROLE_ADMIN";
    public static final String ROLE_MODERATOR = "ROLE_MODERATOR";

    @Id
    private String id;

    private String name;

    public Role(String name) {
        this.name = name;
    }
}
