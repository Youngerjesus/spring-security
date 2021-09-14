package com.example.springbootbasicsecuritydemo.service;

import com.example.springbootbasicsecuritydemo.log.SampleLogger;
import org.springframework.scheduling.annotation.Async;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.Collection;

@Service
public class SampleService {

    public String dashboard() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Object principal = authentication.getPrincipal(); // 사실상 UserDetails Type 일것이다.
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        Object credentials = authentication.getCredentials(); // 아마 null 일 것. 인증을 하고 난다면 Credential 을 이미 가지고 있을 필요는 없으니.
        return principal.toString();
    }

    @Async
    public void asyncService() {
        SampleLogger.log("Async Service processing..."); // TODO SecurityContext 를 참조하는게 불가능하다. 참조할려면 SecurityContext 를 감싸는 전략을 바꿔야한다.
    }


}
