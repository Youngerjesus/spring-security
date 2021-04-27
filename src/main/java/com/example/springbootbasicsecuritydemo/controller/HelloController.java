package com.example.springbootbasicsecuritydemo.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {

    @GetMapping("/")
    public String hello(){
        return "hello";
    }

    @GetMapping("loginPage")
    public String loginPage(){
        return "loginPage";
    }

    @GetMapping("/admin/pay")
    public String adminPay(){
        return "adminPay";
    }

    @GetMapping("/admin/**")
    public String admin(){
        return "admin";
    }

    @GetMapping("/user")
    public String user(){
        return "user";
    }
}
