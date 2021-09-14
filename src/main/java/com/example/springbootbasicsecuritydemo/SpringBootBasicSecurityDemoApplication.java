package com.example.springbootbasicsecuritydemo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableAsync;

@EnableAsync
@SpringBootApplication
public class SpringBootBasicSecurityDemoApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringBootBasicSecurityDemoApplication.class, args);
    }

}
