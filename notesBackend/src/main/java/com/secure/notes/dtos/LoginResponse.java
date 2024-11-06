package com.secure.notes.dtos;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
@AllArgsConstructor
public class LoginResponse {

    private String username;
    private String jwtToken;
    private List<String> roles;

}
