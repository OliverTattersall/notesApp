package com.secure.notes.repositories;

import com.secure.notes.models.AppRoleEnum;
import com.secure.notes.models.Role;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByRoleName(AppRoleEnum appRole);
}
