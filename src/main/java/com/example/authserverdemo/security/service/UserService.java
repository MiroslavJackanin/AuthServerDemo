package com.example.authserverdemo.security.service;

import com.example.authserverdemo.model.User;
import com.example.authserverdemo.payload.request.SignInRequest;
import com.example.authserverdemo.payload.request.SignUpRequest;
import com.example.authserverdemo.security.oauth2.user.OAuth2UserInfo;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;

import javax.naming.AuthenticationException;

public interface UserService {

    User registerNewUser(SignUpRequest signUpRequest) throws AuthenticationException;

    User registerNewOauthUser(OAuth2UserRequest oAuth2UserRequest, OAuth2UserInfo oAuth2UserInfo);

    User updateExistingOauthUser(User existingUser, OAuth2UserInfo oAuth2UserInfo);

    String authenticateUser(SignInRequest loginRequest);
}
