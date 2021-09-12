package com.example.authserverdemo.config;

import com.example.authserverdemo.model.AuthProvider;
import com.example.authserverdemo.model.Role;
import com.example.authserverdemo.model.User;
import com.example.authserverdemo.repository.RoleRepository;
import com.example.authserverdemo.repository.UserRepository;
import org.springframework.context.ApplicationListener;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public class SetupDataLoader implements ApplicationListener<ContextRefreshedEvent> {

    private boolean alreadySetup = false;

    private final UserRepository userRepository;

    private final RoleRepository roleRepository;

    private final PasswordEncoder passwordEncoder;

    public SetupDataLoader(UserRepository userRepository, RoleRepository roleRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void onApplicationEvent(ContextRefreshedEvent contextRefreshedEvent) {
        if (alreadySetup)
            return;

        createRoleIfNotFound(Role.ROLE_USER);
        createRoleIfNotFound(Role.ROLE_ADMIN);
        createRoleIfNotFound(Role.ROLE_MODERATOR);

        User user = createUserIfNotFound();

        if (user != null) {
            printCredentials(user);
            alreadySetup = true;
        }
    }

    private User createUserIfNotFound() {
        Optional<User> optionalUser = userRepository.findByEmail("kasv.project@gmail.com");
        User user;
        if (optionalUser.isEmpty()) {
            user = new User();
            List<Role> roles = new ArrayList<>();
            roles.add(new Role(Role.ROLE_USER));
            roles.add(new Role(Role.ROLE_ADMIN));
            roles.add(new Role(Role.ROLE_MODERATOR));

            user.setName("Admin");
            user.setEmail("kasv.project@gmail.com");
            user.setPassword(passwordEncoder.encode("admin"));
            user.setRoles(roles);
            user.setProvider(AuthProvider.local);
            return userRepository.save(user);
        } else return null;
    }

    private void createRoleIfNotFound(String roleName) {
        Optional<Role> optionalRole = roleRepository.findByName(roleName);
        if (optionalRole.isEmpty()) {
            roleRepository.save(new Role(roleName));
        }
    }

    private void printCredentials(User user) {
        System.out.println("/////ADMIN CREDENTIALS/////");
        System.out.println("NAME:  " + user.getName());
        System.out.println("EMAIL: " + user.getEmail());
        System.out.println("PASS:  admin" );
    }
}
