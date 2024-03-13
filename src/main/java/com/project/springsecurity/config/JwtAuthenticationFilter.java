package com.project.springsecurity.config;

import com.project.springsecurity.services_business.concerets.JWTService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

//JWT Authentication filter and user service, JWT Auth filter is the class where we will validate JWT for every API
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JWTService jwtService;
    private final UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,@NonNull HttpServletResponse response,@NonNull FilterChain filterChain)
            throws ServletException, IOException {
        //we need to take authorization header from the request
        //authHeader = authentication header
        final String authHeader = request.getHeader("Authorization");
        final String jwt; //will store jwt token
        final String userEmail;

        //need to check auth header if its empty or not
        if(authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }
        //extract token from this header
        //get token and store it in jwt
        jwt = authHeader.substring(7);
        //after checking the jwt token, we have to call UserDetailsService to check if we have the user already within our database. But to do that we need to call JwtService to extract username
        userEmail = jwtService.extractUserName(jwt);
        //we have to create JWTService and JWTServiceImp
        if(userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) { //if the user is authenticated don't need to do anything further (do not need to apply UserDetails part)
           //check to see if we have that user already in db, (UserDetailsService part)
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail); //ApplicationConfig
            //validate and check if the token is valid or not
            if(jwtService.isTokenValid(jwt, userDetails)) { //if user valid we need to update SecurityContext and send the request to out dispatcher servlet part
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );
                authToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );
                SecurityContextHolder.getContext().setAuthentication(authToken); //update the authentication token
            }
        }
        filterChain.doFilter(request, response);
    }
}
