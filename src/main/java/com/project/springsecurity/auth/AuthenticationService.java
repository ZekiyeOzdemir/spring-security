package com.project.springsecurity.auth;

import com.project.springsecurity.entities.Role;
import com.project.springsecurity.entities.User;
import com.project.springsecurity.repository.UserRepository;
import com.project.springsecurity.services_business.concerets.JWTService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JWTService jwtService;
    private final AuthenticationManager authenticationManager; //bean. ApplicationConfig'de olusturulmus bean. Hali hazirda AuthenticationManager diye bir sinif var springde sadece service anotasyonu yoktu, bean seklinde olusturduk
    public AuthenticationResponse register(RegisterRequest request) {
        //allow us to create a user save it to the db and return the generated token out of it
        /*
        * if(userServiceRepository.getOneUserbyUserName(request.getUserName()) != null) return new ResponseEntity<>("username already in use", Http.Status.BAD_REQUEST)
        * */
        var user = User.builder()
                .firstname(request.getFirstname())
                .lastname(request.getLastname())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .build();
        userRepository.save(user); /*return new ResponseEntity<>("username already in use", Http.Status.CREATED)*/
        var jwtToken = jwtService.generateToken(user);
        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword()));
        var user = userRepository.findByEmail(request.getEmail()).orElseThrow();
        var jwtToken = jwtService.generateToken(user);
        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }
}
