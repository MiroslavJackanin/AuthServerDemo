package com.example.authserverdemo.security.service;

import com.example.authserverdemo.model.AuthProvider;
import com.example.authserverdemo.model.User;
import com.example.authserverdemo.payload.request.SignInRequest;
import com.example.authserverdemo.payload.request.SignUpRequest;
import com.example.authserverdemo.repository.UserRepository;
import com.example.authserverdemo.security.jwt.JWTokenProvider;
import com.example.authserverdemo.security.oauth2.user.OAuth2UserInfo;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.stereotype.Service;

import javax.naming.AuthenticationException;

@Service
public class UserServiceImpl implements UserService {

    private final AuthenticationManager authenticationManager;

    private final JWTokenProvider jwTokenProvider;

    private final UserRepository userRepository;

    private final PasswordEncoder passwordEncoder;

    public UserServiceImpl(AuthenticationManager authenticationManager, JWTokenProvider jwTokenProvider, UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.authenticationManager = authenticationManager;
        this.jwTokenProvider = jwTokenProvider;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public User registerNewUser(SignUpRequest signUpRequest) throws AuthenticationException {

        if(userRepository.existsByEmail(signUpRequest.getEmail())) {
            throw new AuthenticationException("Email: " + signUpRequest.getEmail() + " is already in use");
        }

        User user = new User();
        user.setName(signUpRequest.getName());
        user.setEmail(signUpRequest.getEmail());
        user.setPassword(signUpRequest.getPassword());
        user.setProvider(AuthProvider.local);
        user.setPassword(passwordEncoder.encode(user.getPassword()));

        return userRepository.save(user);
    }

    @Override
    public User registerNewOauthUser(OAuth2UserRequest oAuth2UserRequest, OAuth2UserInfo oAuth2UserInfo) {

        User user = new User();
        user.setProvider(AuthProvider.valueOf(oAuth2UserRequest.getClientRegistration().getRegistrationId()));
        user.setProviderId(oAuth2UserInfo.getId());
        user.setName(oAuth2UserInfo.getName());
        user.setEmail(oAuth2UserInfo.getEmail());
        user.setImageUrl(oAuth2UserInfo.getImageUrl());

        return userRepository.save(user);
    }

    @Override
    public User updateExistingOauthUser(User existingUser, OAuth2UserInfo oAuth2UserInfo) {

        existingUser.setName(oAuth2UserInfo.getName());
        existingUser.setImageUrl(oAuth2UserInfo.getImageUrl());
        return userRepository.save(existingUser);
    }

    @Override
    public String authenticateUser(SignInRequest signInRequest) {

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        signInRequest.getEmail(),
                        signInRequest.getPassword()
                )
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);

        return jwTokenProvider.createToken(authentication);
    }
}
