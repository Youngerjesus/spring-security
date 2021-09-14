package com.example.springbootbasicsecuritydemo.controller;

import com.example.springbootbasicsecuritydemo.service.SampleService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class SampleController {

    private final SampleService sampleService;

    @GetMapping("/dashboard")
    public String dashboard() {
        return sampleService.dashboard();
    }
}
