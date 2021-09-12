package com.example.authserverdemo.security.oauth2;

import com.example.authserverdemo.exception.OAuth2AuthenticationProcessingException;
import com.example.authserverdemo.model.AuthProvider;
import com.example.authserverdemo.model.User;
import com.example.authserverdemo.repository.UserRepository;
import com.example.authserverdemo.security.UserPrincipal;
import com.example.authserverdemo.security.oauth2.user.OAuth2UserFactory;
import com.example.authserverdemo.security.oauth2.user.OAuth2UserInfo;
import com.example.authserverdemo.security.service.UserServiceImpl;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.util.Optional;

@Service
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;

    private final UserServiceImpl userService;

    public CustomOAuth2UserService(UserRepository userRepository, UserServiceImpl userService) {
        this.userRepository = userRepository;
        this.userService = userService;
    }

    @Override
    public OAuth2User loadUser(OAuth2UserRequest oAuth2UserRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(oAuth2UserRequest);

        try {
            return processOAuth2User(oAuth2UserRequest, oAuth2User);
        } catch (AuthenticationException e) {
            throw e;
        } catch (Exception e) {
            throw new InternalAuthenticationServiceException(e.getMessage(), e.getCause());
        }
    }

    private OAuth2User processOAuth2User(OAuth2UserRequest oAuth2UserRequest, OAuth2User oAuth2User) {

        OAuth2UserInfo oAuth2UserInfo = OAuth2UserFactory.getOAuth2UserInfo(
                oAuth2UserRequest.getClientRegistration().getRegistrationId(),
                oAuth2User.getAttributes());

        if(!StringUtils.hasText(oAuth2UserInfo.getEmail())) {
            throw new OAuth2AuthenticationProcessingException("Email not found from OAuth2 provider");
        }

        Optional<User> optionalUser = userRepository.findByEmail(oAuth2UserInfo.getEmail());
        User user;
        if(optionalUser.isPresent()) {
            user = optionalUser.get();
            if(!user.getProvider().equals(AuthProvider.valueOf(oAuth2UserRequest.getClientRegistration().getRegistrationId()))) {
                throw new OAuth2AuthenticationProcessingException("You are already signed up with your " + user.getProvider() + " account.");
            }
            user = userService.updateExistingOauthUser(user, oAuth2UserInfo);
        } else {
            user = userService.registerNewOauthUser(oAuth2UserRequest, oAuth2UserInfo);
        }
        return UserPrincipal.create(user, oAuth2User.getAttributes());
    }
}
