package com.secure.notes.controllers;

import com.secure.notes.dtos.UserDTO;
import com.secure.notes.models.User;
import com.secure.notes.services.UserService;
import jakarta.annotation.security.RolesAllowed;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.annotation.Secured;
import org.springframework.web.bind.annotation.*;

import java.util.List;



@RestController
@RequestMapping("/api/admin")
@Secured("ROLE_ADMIN") // applies for all methods, can also apply at service level
public class AdminController {

    @Autowired
    UserService userService;


//    @Secured("ROLE_ADMIN")
    @GetMapping("/getusers")
    public ResponseEntity<List<User>> getAllUsers(){
        return new ResponseEntity<>(userService.getAllUsers(), HttpStatus.OK);
    }

//    @Secured("ROLE_ADMIN")
    @PutMapping("/update-role")
    public ResponseEntity<String> updateUserRole(@RequestParam Long userId, @RequestParam String roleName){
        userService.updateUserRole(userId, roleName);
        return ResponseEntity.ok("User role updated");
    }

//    @Secured("ROLE_ADMIN")
    @GetMapping("/user/{id}")
    public ResponseEntity<UserDTO> getUser(@PathVariable Long id){
        return new ResponseEntity<UserDTO>(userService.getUserById(id), HttpStatus.OK);
    }

}
