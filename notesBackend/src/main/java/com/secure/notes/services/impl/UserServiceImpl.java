package com.secure.notes.services.impl;

import com.secure.notes.dtos.UserDTO;
import com.secure.notes.models.AppRoleEnum;
import com.secure.notes.models.Role;
import com.secure.notes.models.User;
import com.secure.notes.repositories.RoleRepository;
import com.secure.notes.repositories.UserRepository;
import com.secure.notes.services.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class UserServiceImpl implements UserService {
    @Autowired
    RoleRepository roleRepository;

    @Autowired
    UserRepository userRepository;
    @Override
    public void updateUserRole(Long userId, String roleName){
        User user = userRepository.findById(userId).orElseThrow(()->new RuntimeException("bad user id"));
        AppRoleEnum appRole = AppRoleEnum.valueOf(roleName);
        Role role = roleRepository.findByRoleName(appRole)
                .orElseThrow(()->new RuntimeException("bad role"));
        user.setRole(role);
        userRepository.save(user);
    }

    @Override
    public List<User> getAllUsers(){
        return userRepository.findAll();
    }

    private UserDTO convertToDto(User user) {
        return new UserDTO(
                user.getUserId(),
                user.getUserName(),
                user.getEmail(),
                user.isAccountNonLocked(),
                user.isAccountNonExpired(),
                user.isCredentialsNonExpired(),
                user.isEnabled(),
                user.getCredentialsExpiryDate(),
                user.getAccountExpiryDate(),
                user.getTwoFactorSecret(),
                user.isTwoFactorEnabled(),
                user.getSignUpMethod(),
                user.getRole(),
                user.getCreatedDate(),
                user.getUpdatedDate()
        );
    }
    @Override
    public UserDTO getUserById(Long id){
        User user = userRepository.findById(id).orElseThrow();
        return convertToDto(user);
    }


    @Override
    public User findByUsername(String username){
        Optional<User> user = userRepository.findByUserName(username);
        return user.orElseThrow(()-> new RuntimeException("User not found: " + username));
    }
}
