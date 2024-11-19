package com.gperi.service;

import java.util.List;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.gperi.model.User;
import com.gperi.repository.UserRepository;

@Service
public class UserService {

    @Autowired
    private UserRepository userRepository;

    public List<User> getAllUser() {
        List<User> allUsers = userRepository.findAll();
        
        // Filter out the user with ID 1
        List<User> filteredUsers = allUsers.stream()
                                           .filter(user -> user.getId() != 1)
                                           .collect(Collectors.toList());
        
        return filteredUsers;
    }
}
