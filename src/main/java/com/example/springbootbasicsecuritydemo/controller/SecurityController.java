package com.example.springbootbasicsecuritydemo.controller;

import com.example.springbootbasicsecuritydemo.log.SampleLogger;
import com.example.springbootbasicsecuritydemo.service.SampleService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpSession;
import java.util.concurrent.Callable;

@Slf4j
@RestController
@RequiredArgsConstructor
public class SecurityController {

    private final SampleService sampleService;

    @GetMapping("/authentication")
    public String index(HttpSession session){

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        SecurityContext context = (SecurityContext) session.getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
        Authentication authentication1 = context.getAuthentication();

        return String.format("SecurityContextHolder - principle: %s  \n Session - Principle: %s",
                authentication.getPrincipal().toString(), authentication1.getPrincipal().toString());
    }

    @GetMapping("/thread-local")
    public String thread(){
        new Thread(() -> {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            log.info(Thread.currentThread().getName() + ": authentication " + authentication.toString());
        }).start();

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        log.info(Thread.currentThread().getName() + "-main: authentication " + authentication.toString());
        return "ok";
    }

    @GetMapping("/async-handler")
    public Callable<String> asyncHandler() {
        SampleLogger.log("Async Handler Before");
        return () -> {
            SampleLogger.log("Async Handler After");
            return "Callable";
        };
    }

    @GetMapping("/async-service")
    public String asyncService() {
        SampleLogger.log("Async Service Before");
        sampleService.asyncService();
        SampleLogger.log("Async Service After");
        return "asyncService";
    }
}
