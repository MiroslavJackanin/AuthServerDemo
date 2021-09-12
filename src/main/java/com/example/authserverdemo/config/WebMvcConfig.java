package com.example.authserverdemo.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebMvcConfig implements WebMvcConfigurer {

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        long MAX_AGE_SECS = 3600;

        registry.addMapping("/**")
                .allowedOrigins("http://localhost:4200")
                .allowedMethods("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")
                .allowedHeaders("Content-Type")
                .allowCredentials(true)
                .maxAge(MAX_AGE_SECS);

        registry.addMapping("/public")
                .allowedOrigins("*")
                .allowedMethods("GET")
                .allowedHeaders("Content-Type")
                .allowCredentials(true)
                .maxAge(MAX_AGE_SECS);
    }
}