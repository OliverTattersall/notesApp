package com.secure.notes.security;

import com.secure.notes.models.AppRoleEnum;
import com.secure.notes.models.Role;
import com.secure.notes.models.User;
import com.secure.notes.repositories.RoleRepository;
import com.secure.notes.repositories.UserRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.boot.CommandLineRunner;

import javax.sql.DataSource;
import java.time.LocalDate;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    // create own Security Filter Chain Bean to override default in SpringBootWebSecurityConfiguration.class
    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        // for learning
//        http.authorizeHttpRequests((requests) -> {
//                    ((AuthorizeHttpRequestsConfigurer.AuthorizedUrl) requests
//                            .requestMatchers("/contact").permitAll() // for unauthenticated routes, can add /public/** to add all requests with /public/
//                            .requestMatchers("/admin/**").denyAll() // deny all at this endpoint, for like maintenance or other reasons
//                            .anyRequest()).authenticated();
//                })
//                .csrf(AbstractHttpConfigurer::disable) // disable csrf for now
////          .formLogin(Customizer.withDefaults()) // we don't want the login form
//                .sessionManagement(session ->
//                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) // to make it stateless, remove JSESSION cookie
//                .httpBasic(Customizer.withDefaults());

        http.authorizeHttpRequests((requests) -> requests.anyRequest().authenticated())
        .csrf(AbstractHttpConfigurer::disable)
                .httpBasic(Customizer.withDefaults());

        return (SecurityFilterChain) http.build();
    }



    // static in memory authentication. create 2 users with roles
    // you would delete this as soon as you set up DB/persistent users
    // for testing and POC
    // note memUserDetailsManager implements UserDetaulsManager ixtends UserDetailsServic
//    @Bean
//    public UserDetailsService userDetailsService() {
//        InMemoryUserDetailsManager manager =
//                new InMemoryUserDetailsManager();
//        if (!manager.userExists("user1")) {
//            manager.createUser(
//                    User.withUsername("user1")
//                            .password("{noop}password1") // noop means no encryption
//                            .roles("USER")
//                            .build()
//            );
//        }
//        if (!manager.userExists("admin")) {
//            manager.createUser(
//                    User.withUsername("admin")
//                            .password("{noop}adminPass")
//                            .roles("ADMIN")
//                            .build()
//            );
//        }
//        return manager;
//    }
//

////     DataSource is automatically injected and passed based on pom.xml and properties, so SQL in this case
//    @Bean
//    public UserDetailsService userDetailsService(DataSource dataSource){
//        JdbcUserDetailsManager manager = new JdbcUserDetailsManager(dataSource);
//
//        // not necessary for real production code
//        if (!manager.userExists("user1")) {
//            manager.createUser(
//                    User.withUsername("user1")
//                            .password("{noop}password1") // noop means no encryption
//                            .roles("USER")
//                            .build()
//            );
//        }
//        if (!manager.userExists("admin")) {
//            manager.createUser(
//                    User.withUsername("admin")
//                            .password("{noop}adminPass")
//                            .roles("ADMIN")
//                            .build()
//            );
//        }
//        return manager;
//    }


    // method to fill database if empty, not needed in real production
    @Bean
    public CommandLineRunner initData(RoleRepository roleRepository, UserRepository userRepository) {
        return args -> {
            Role userRole = roleRepository.findByRoleName(AppRoleEnum.ROLE_USER)
                    .orElseGet(() -> roleRepository.save(new Role(AppRoleEnum.ROLE_USER)));

            Role adminRole = roleRepository.findByRoleName(AppRoleEnum.ROLE_ADMIN)
                    .orElseGet(() -> roleRepository.save(new Role(AppRoleEnum.ROLE_ADMIN)));

            // make sure to use customUser not standard user
            if (!userRepository.existsByUserName("user1")) {
                User user1 = new User("user1", "user1@example.com", "{noop}password1");
                user1.setAccountNonLocked(false);
                user1.setAccountNonExpired(true);
                user1.setCredentialsNonExpired(true);
                user1.setEnabled(true);
                user1.setCredentialsExpiryDate(LocalDate.now().plusYears(1));
                user1.setAccountExpiryDate(LocalDate.now().plusYears(1));
                user1.setTwoFactorEnabled(false);
                user1.setSignUpMethod("email");
                user1.setRole(userRole);
                userRepository.save(user1);
            }

            if (!userRepository.existsByUserName("admin")) {
                User admin = new User("admin", "admin@example.com", "{noop}adminPass");
                admin.setAccountNonLocked(true);
                admin.setAccountNonExpired(true);
                admin.setCredentialsNonExpired(true);
                admin.setEnabled(true);
                admin.setCredentialsExpiryDate(LocalDate.now().plusYears(1));
                admin.setAccountExpiryDate(LocalDate.now().plusYears(1));
                admin.setTwoFactorEnabled(false);
                admin.setSignUpMethod("email");
                admin.setRole(adminRole);
                userRepository.save(admin);
            }
        };
    }
}
