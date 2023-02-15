//package com.example.spring_security_2023_amigo.controllers;
//
//import com.example.spring_security_2023_amigo.config.JwtUtils;
//import com.example.spring_security_2023_amigo.config.UserService;
//import com.example.spring_security_2023_amigo.dto.AuthenticationRequest;
//import lombok.RequiredArgsConstructor;
//import org.springframework.http.ResponseEntity;
//import org.springframework.security.authentication.AuthenticationManager;
//import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
//import org.springframework.security.core.userdetails.UserDetails;
//import org.springframework.web.bind.annotation.*;
//
//@RestController
//@RequestMapping("/api/v1/auth")
//@RequiredArgsConstructor
//public class AuthenticationController {
//
//    private final AuthenticationManager authenticationManager;
//    private final UserService userService;
//    private final JwtUtils jwtUtils;
//
//    @PostMapping
//    public ResponseEntity<String> authenticate(@RequestBody AuthenticationRequest request){
//        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword()));
//        final UserDetails user = userService.loadUserByUsername(request.getEmail());
//        if (user != null) {
//            return ResponseEntity.ok(jwtUtils.generateToken(user));
//        }
//        return ResponseEntity.badRequest().body("Some error has occurred");
//    }
//}
