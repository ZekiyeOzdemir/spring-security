package com.project.springsecurity.services_business.impl;

import com.project.springsecurity.services_business.concerets.JWTService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

//or JWTServiceManager
//Jwt Service process at schema
@Service
public class JWTServiceImp implements JWTService {
    private static final String SECRET_KEY = "404E635266556A586E3272357538782F413F4428472B4B6250645367566B5970";
    //methods that can generate the jwt or extract any info from our token or can check some fields of the token

    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    private String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) { //help us to generate token
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername()) //subject is user email
                .setIssuedAt(new Date(System.currentTimeMillis())) //calculate if token is valid or not
                .setExpiration(new Date(System.currentTimeMillis() + 1000*60*24)) //how long this token should be valid
                .signWith(getSignInKey(), SignatureAlgorithm.HS256) //to declare which key we should to use sign this token
                .compact(); //compact is generate and return the token. userDetails ve extraClaimsler ile token generate ettik
    }

    //method that will validate or can validate a token
    public boolean isTokenValid(String token, UserDetails userDetails) { //validate to if this token belongs the this userDetails
        final String username = extractUserName(token); //username is email here
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    //for get the username, will return email
    public String extractUserName(String token) {
        return extractClaim(token, Claims::getSubject); //subject is email of user
    }

    private <T> T extractClaim(String token, Function<Claims, T> claimResolvers) {
        final Claims claims = extractAllClaims(token);
        return claimResolvers.apply(claims);
    }

    private SecretKey getSignInKey() {
        byte[] key = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(key);
    }

    private Claims extractAllClaims(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey()) //signinkey used to create the signature part of the JWT which is used to verify that the sender of the JWT is who it claims to be and ensure that message wasn't changed along the way
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}
