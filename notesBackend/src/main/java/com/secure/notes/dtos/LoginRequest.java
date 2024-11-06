package com.secure.notes.dtos;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class LoginRequest { // format for a login request
    private String username;

    private String password;

}

