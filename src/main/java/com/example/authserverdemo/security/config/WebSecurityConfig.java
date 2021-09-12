package com.example.authserverdemo.security.config;

import com.example.authserverdemo.security.RestAuthenticationEntryPoint;
import com.example.authserverdemo.security.oauth2.CustomOAuth2UserService;
import com.example.authserverdemo.security.oauth2.OAuth2AuthenticationFailureHandler;
import com.example.authserverdemo.security.oauth2.OAuth2AuthenticationSuccessHandler;
import com.example.authserverdemo.security.oauth2.OAuth2AuthorizationRequestRepository;
import com.example.authserverdemo.security.service.UserDetailsServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(
        securedEnabled = true,
        jsr250Enabled = true
)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    private CustomOAuth2UserService oAuth2UserService;

    private final UserDetailsServiceImpl userDetailsService;

    private final OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler;

    private final OAuth2AuthenticationFailureHandler oAuth2AuthenticationFailureHandler;

    private final OAuth2AuthorizationRequestRepository oAuth2AuthorizationRequestRepository;

    public WebSecurityConfig(UserDetailsServiceImpl userDetailsService, OAuth2AuthorizationRequestRepository oAuth2AuthorizationRequestRepository, OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler, OAuth2AuthenticationFailureHandler oAuth2AuthenticationFailureHandler) {
        this.userDetailsService = userDetailsService;
        this.oAuth2AuthorizationRequestRepository = oAuth2AuthorizationRequestRepository;
        this.oAuth2AuthenticationSuccessHandler = oAuth2AuthenticationSuccessHandler;
        this.oAuth2AuthenticationFailureHandler = oAuth2AuthenticationFailureHandler;
    }

    @Autowired
    public void setCustomOAuth2UserService(@Lazy CustomOAuth2UserService oAuth2UserService) {
        this.oAuth2UserService = oAuth2UserService;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean(BeanIds.AUTHENTICATION_MANAGER)
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Override
    public void configure(AuthenticationManagerBuilder authenticationManagerBuilder) throws Exception {
        authenticationManagerBuilder
                .userDetailsService(userDetailsService)
                .passwordEncoder(passwordEncoder());
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        sessionCreationPolicy(http);
        loginAndLogout(http);
        exceptionHandling(http);
        csrf(http);
        cors(http);
        oauth2Client(http);
        authorizeRequests(http);
    }

    protected void sessionCreationPolicy(HttpSecurity http) throws Exception {

        http.sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS);
    }

    protected void loginAndLogout(HttpSecurity http) throws Exception {

        http.formLogin().disable();
        http.logout().disable();
    }

    protected void exceptionHandling(HttpSecurity http) throws Exception {

        http.exceptionHandling()
                .authenticationEntryPoint(new RestAuthenticationEntryPoint());
    }

    protected void csrf(HttpSecurity http) throws Exception {

        http.csrf().disable();
    }

    protected void cors(HttpSecurity http) throws Exception {

        http.cors();
    }

    private void oauth2Client(HttpSecurity http) throws Exception {

        http.oauth2Login()
                .authorizationEndpoint()
                        .baseUri("/oauth2/authorize")
                .authorizationRequestRepository(oAuth2AuthorizationRequestRepository).and()
                .redirectionEndpoint()
                        .baseUri("/oauth2/callback/*").and()
                .userInfoEndpoint()
                        .userService(oAuth2UserService).and()
                .successHandler(oAuth2AuthenticationSuccessHandler)
                .failureHandler(oAuth2AuthenticationFailureHandler);
    }

    protected void authorizeRequests(HttpSecurity http) throws Exception {

        http.authorizeRequests()
                .antMatchers("/auth/**", "/oauth2/**")
                        .permitAll()
                .anyRequest()
                        .authenticated();
    }
}
