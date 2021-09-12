package com.example.authserverdemo;

import com.example.authserverdemo.config.AppProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties(AppProperties.class)
public class AuthServerDemoApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthServerDemoApplication.class, args);
    }

}
