package org.apply.server.configuration;

import lombok.RequiredArgsConstructor;
import org.apply.core.AasConstant;
import org.apply.core.userdetails.AasUser;
import org.apply.server.event.AuthenticationEventListener;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import java.util.Collections;

@EnableWebSecurity
@RequiredArgsConstructor
@Configuration(proxyBeanMethods = false)
public class DefaultSecurityConfiguration {

    private final SessionRegistry sessionRegistry;

    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {

        http.authorizeHttpRequests(customizer -> {
            customizer.requestMatchers("/assets/**", AasConstant.LOGIN_PAGE)
                    .permitAll()
                    .anyRequest()
                    .authenticated();
        });

        http.formLogin(formLogin -> {
            formLogin.loginPage(AasConstant.LOGIN_PAGE);
        });

        http.logout(Customizer.withDefaults());

        http.sessionManagement(sessionManagement -> {
            sessionManagement.sessionConcurrency(sessionConcurrency -> {
                sessionConcurrency.maximumSessions(1);
                sessionConcurrency.sessionRegistry(sessionRegistry);
                sessionConcurrency.expiredUrl(AasConstant.LOGIN_PAGE);
            });
        });

        return http.build();
    }

    @Bean
    public AuthenticationEventListener authenticationEventListener() {
        return new AuthenticationEventListener();
    }

    @Bean
    public UserDetailsService users() {
        AasUser user = new AasUser();
        user.setUsername("user1");
        user.setPassword(AasConstant.PASSWORD_ENCODER.encode("password"));
        user.setAuthorities(Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")));
        return new InMemoryUserDetailsManager(user);
    }

}
