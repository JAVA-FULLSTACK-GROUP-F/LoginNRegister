package com.unimap.zerohunger.repo;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.unimap.zerohunger.model.Role;
 
@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
 
    Role findByName(String name);
}