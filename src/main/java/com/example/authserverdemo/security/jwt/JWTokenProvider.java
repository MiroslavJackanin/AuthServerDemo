package com.example.authserverdemo.security.jwt;

import com.example.authserverdemo.config.AppProperties;
import com.example.authserverdemo.security.UserPrincipal;
import io.jsonwebtoken.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import java.util.Date;

@Service
public class JWTokenProvider {

    private final AppProperties appProperties;

    private final JWTokenKeyProvider jwTokenKeyProvider;

    private static final Logger logger = LoggerFactory.getLogger(JWTokenProvider.class);

    public JWTokenProvider(AppProperties appProperties, JWTokenKeyProvider jwTokenKeyProvider) {
        this.appProperties = appProperties;
        this.jwTokenKeyProvider = jwTokenKeyProvider;
    }

    public String createToken(Authentication authentication) {
        UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();

        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + appProperties.getAuth().getTokenExpirationMs());

        return Jwts.builder()
                .setSubject(userPrincipal.getId())
                .claim("roles", String.valueOf(userPrincipal.getAuthorities()))
                .setIssuedAt(new Date())
                .setExpiration(expiryDate)
                .signWith(SignatureAlgorithm.RS256, jwTokenKeyProvider.getPrivateKey())
                .compact();
    }

    public String getUserIdFromToken(String token) {
        return Jwts.parser().setSigningKey(jwTokenKeyProvider.getPublicKey()).parseClaimsJws(token).getBody().getSubject();
    }

    public boolean validateToken(String authToken) {
        try {
            Jwts.parser().setSigningKey(jwTokenKeyProvider.getPublicKey()).parseClaimsJws(authToken);
            return true;
        } catch (MalformedJwtException ex) {
            logger.error("Invalid JWT token");
        } catch (ExpiredJwtException ex) {
            logger.error("Expired JWT token");
        } catch (UnsupportedJwtException ex) {
            logger.error("Unsupported JWT token");
        } catch (IllegalArgumentException ex) {
            logger.error("JWT claims string is empty.");
        }
        return false;
    }
}
