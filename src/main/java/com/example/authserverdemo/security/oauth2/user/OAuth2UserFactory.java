package com.example.authserverdemo.security.oauth2.user;

import com.example.authserverdemo.exception.OAuth2AuthenticationProcessingException;
import com.example.authserverdemo.model.AuthProvider;

import java.util.Map;

public class OAuth2UserFactory {

    public static OAuth2UserInfo getOAuth2UserInfo(String registrationId, Map<String, Object> attributes) {
        if(registrationId.equalsIgnoreCase(AuthProvider.google.toString())) {
            return new GoogleOAuth2User(attributes);
        } else if (registrationId.equalsIgnoreCase(AuthProvider.facebook.toString())) {
            return new FacebookOAuth2User(attributes);
        } else if (registrationId.equalsIgnoreCase(AuthProvider.github.toString())) {
            return new GithubOAuth2User(attributes);
        } else {
            throw new OAuth2AuthenticationProcessingException(registrationId + " is not a supported provider yet.");
        }
    }
}
