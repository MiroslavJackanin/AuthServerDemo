package com.example.authserverdemo.security.oauth2;

import com.example.authserverdemo.utility.CookieUtils;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Component
public class OAuth2AuthorizationRequestRepository implements AuthorizationRequestRepository<OAuth2AuthorizationRequest> {

    public static final String OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME = "oauth2_auth_request";
    public static final String REDIRECT_URI_PARAM_COOKIE_NAME = "redirect_uri";
    private static final int COOKIE_EXPIRATION_SECS = 180;

    @Override
    public OAuth2AuthorizationRequest loadAuthorizationRequest(HttpServletRequest httpServletRequest) {
        return CookieUtils.getCookie(httpServletRequest, OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME)
                .map(cookie -> CookieUtils.deserialize(cookie, OAuth2AuthorizationRequest.class))
                .orElse(null);
    }

    @Override
    public void saveAuthorizationRequest(OAuth2AuthorizationRequest oAuth2AuthorizationRequest, HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) {
        if (oAuth2AuthorizationRequest == null) {
            CookieUtils.deleteCookie(httpServletRequest, httpServletResponse, OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME);
            CookieUtils.deleteCookie(httpServletRequest, httpServletResponse, REDIRECT_URI_PARAM_COOKIE_NAME);
            return;
        }

        CookieUtils.addCookie(httpServletResponse, OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME, CookieUtils.serialize(oAuth2AuthorizationRequest), COOKIE_EXPIRATION_SECS);
        String redirectUriAfterLogin = httpServletRequest.getParameter(REDIRECT_URI_PARAM_COOKIE_NAME);
        if (StringUtils.isNotBlank(redirectUriAfterLogin)) {
            CookieUtils.addCookie(httpServletResponse, REDIRECT_URI_PARAM_COOKIE_NAME, redirectUriAfterLogin, COOKIE_EXPIRATION_SECS);
        }
    }

    @Override
    public OAuth2AuthorizationRequest removeAuthorizationRequest(HttpServletRequest httpServletRequest) {
        return this.loadAuthorizationRequest(httpServletRequest);
    }

    public void removeAuthorizationRequestCookies(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) {
        CookieUtils.deleteCookie(httpServletRequest, httpServletResponse, OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME);
        CookieUtils.deleteCookie(httpServletRequest, httpServletResponse, REDIRECT_URI_PARAM_COOKIE_NAME);
    }
}
