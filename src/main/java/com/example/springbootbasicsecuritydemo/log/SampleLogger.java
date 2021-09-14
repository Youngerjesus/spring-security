package com.example.springbootbasicsecuritydemo.log;

import org.springframework.security.core.context.SecurityContextHolder;

public class SampleLogger {
    public static void log(String message) {
        System.out.println(message);
        Thread thread = Thread.currentThread();
        System.out.println(thread.getName());
        System.out.println(SecurityContextHolder.getContext().getAuthentication().toString());
    }
}
