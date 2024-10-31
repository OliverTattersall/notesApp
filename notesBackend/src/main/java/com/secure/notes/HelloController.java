package com.secure.notes;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {
    @GetMapping("/hello")
    public String getHelloWorld() {
        return "Hello World";
    }

    @GetMapping("contact")
    public String getContact() {
        return "Made Contact";
    }
}
