package com.unimap.zerohunger.repo;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.unimap.zerohunger.model.User;
 
@Repository
public interface UserRepository extends JpaRepository<User, Long> {
 
    User findByEmail(String email);
 
    boolean existsByEmail(String email);
 
}
