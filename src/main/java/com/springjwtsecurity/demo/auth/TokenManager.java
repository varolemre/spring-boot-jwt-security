package com.springjwtsecurity.demo.auth;

import io.jsonwebtoken.Claims;
import org.springframework.stereotype.Service;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import java.security.Key;
import java.util.Date;

import static io.jsonwebtoken.Jwts.*;

@Service
public class TokenManager {

    private static final int validity = 5 * 60 *1000;
    Key key = Keys.secretKeyFor(SignatureAlgorithm.HS256);

    public String generateToken(String username){
        Key key = Keys.secretKeyFor(SignatureAlgorithm.HS256);

        return builder()
                .setSubject(username)
                .setIssuer("Mavialev1.com")
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis()+validity))
                .signWith(key)
                .compact();
    }

    public boolean tokenValidate(String token){
        if(getUsernameToken(token) != null && isExpired(token)){
            return true;
        }
        return false;
    }

    public String getUsernameToken(String token){
        Claims claims = getClaims(token);
        return claims.getSubject();
    }

    public boolean isExpired(String token){
        Claims claims = getClaims(token);
        return claims.getExpiration().after(new Date((System.currentTimeMillis())));
    }

    private Claims getClaims(String token) {
        return parser().setSigningKey(key).parseClaimsJwt(token).getBody();
    }
}
