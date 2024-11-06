package com.secure.notes.security;

import com.secure.notes.models.AppRoleEnum;
import com.secure.notes.models.Role;
import com.secure.notes.models.User;
import com.secure.notes.repositories.RoleRepository;
import com.secure.notes.repositories.UserRepository;
import com.secure.notes.security.jwt.AuthEntryPointJwt;
import com.secure.notes.security.jwt.AuthTokenFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

import javax.sql.DataSource;
import java.time.LocalDate;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true, securedEnabled = true, jsr250Enabled = true) // enables using method elvel security, prePostenable fro Pre Post se
// securedEnabled for @Secured, jsr250 for roles allowed, we are using url based restrictions
public class SecurityConfig {

    @Autowired
    private AuthEntryPointJwt unauthorizedHandler;

    @Bean
    public AuthTokenFilter authenticationJwtTokenFilter(){
        return new AuthTokenFilter();
    }

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

        http
            .csrf(csrf ->
//                    csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())) // makes the cookie not only http which means we can write it, this is bad in production
                    csrf.csrfTokenRepository(new CookieCsrfTokenRepository()) // this will have httpOnly
                            .ignoringRequestMatchers("/api/auth/public/**") // ignore csrf protection for all urls matching this
            )
            .authorizeHttpRequests(
                (requests) -> requests
                        .requestMatchers("/api/auth/**").permitAll() // opens auth
                        .requestMatchers("/api/csrf-token").permitAll() // to get csrf token
//                        .requestMatchers("/api/admin/**").hasRole("ADMIN") // can use this instead of method level. note hasRole appends ROLE_ at start
                        .anyRequest().authenticated()
                )
            .exceptionHandling(exception -> exception.authenticationEntryPoint(unauthorizedHandler)) // setting exception handling to the handler
            .addFilterBefore(authenticationJwtTokenFilter(), UsernamePasswordAuthenticationFilter.class) // adding jwt filter before password auth
            .addFilterBefore(new CustomLoggingFilter(), AuthTokenFilter.class) // makes custom filter happen before authentication
//            .addFilterAfter(new RequestValidationFilter(), CustomLoggingFilter.class) // adds it right after logging, just for an example
//            .httpBasic(Customizer.withDefaults());
        ;

        return (SecurityFilterChain) http.build();
    }

    @Bean // we need to make this bean so anywhere we autowire an authentication manager, it can get it from here
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    // setting password encoder to BCrypt, now anywhere we need a password encoder, it will use that
    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
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
    public CommandLineRunner initData(RoleRepository roleRepository, UserRepository userRepository, PasswordEncoder passwordEncoder) {
        return args -> {
            Role userRole = roleRepository.findByRoleName(AppRoleEnum.ROLE_USER)
                    .orElseGet(() -> roleRepository.save(new Role(AppRoleEnum.ROLE_USER)));

            Role adminRole = roleRepository.findByRoleName(AppRoleEnum.ROLE_ADMIN)
                    .orElseGet(() -> roleRepository.save(new Role(AppRoleEnum.ROLE_ADMIN)));

            // make sure to use customUser not standard user
            if (!userRepository.existsByUserName("user1")) {
                User user1 = new User("user1", "user1@example.com", passwordEncoder.encode("password1"));
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
                User admin = new User("admin", "admin@example.com", passwordEncoder.encode("adminPass"));
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
