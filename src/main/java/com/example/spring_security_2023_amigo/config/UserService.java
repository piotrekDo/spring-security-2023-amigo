package com.example.spring_security_2023_amigo.config;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

@Component
public class UserService implements UserDetailsService {

    private final static List<UserDetails> APPLICATION_USERS = Arrays.asList(
            new User("test@email.com", "password", Collections.singletonList(new SimpleGrantedAuthority("ROLE_ADMIN"))),
            new User("test22@email.com", "password", Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")))
    );

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return APPLICATION_USERS.stream()
                .filter(u -> u.getUsername().equals(username))
                .findFirst()
                .orElseThrow();
    }
}
