package org.apply.server.configuration;

import org.apply.core.SecurityConstants;
import org.apply.core.userdetails.AasUser;
import org.apply.server.event.AuthenticationEventListener;
import org.apply.server.support.filter.PreCaptchaVerifyFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.Collections;

@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
public class DefaultSecurityConfiguration {

    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http, SessionRegistry sessionRegistry) throws Exception {

        http.authorizeHttpRequests(customizer -> {
            customizer.requestMatchers("/assets/**", SecurityConstants.OAUTH_LOGIN_URI)
                    .permitAll()
                    .anyRequest()
                    .authenticated();
        });

        http.formLogin(customizer -> {
            customizer.loginPage(SecurityConstants.OAUTH_LOGIN_URI);
            customizer.failureForwardUrl(SecurityConstants.OAUTH_LOGIN_URI);
        });

        http.sessionManagement(sessionManagement -> sessionManagement.sessionConcurrency(sessionConcurrency -> {
            sessionConcurrency.maximumSessions(1);
            sessionConcurrency.sessionRegistry(sessionRegistry);
            sessionConcurrency.expiredUrl(SecurityConstants.OAUTH_LOGIN_URI);
        }));

        http.logout(Customizer.withDefaults());

        http.addFilterBefore(new PreCaptchaVerifyFilter(), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return SecurityConstants.PASSWORD_ENCODER;
    }

    @Bean
    public AuthenticationEventListener authenticationEventListener() {
        return new AuthenticationEventListener();
    }

    @Bean
    public UserDetailsService users() {
        AasUser user = new AasUser();
        user.setUserId("userId");
        user.setUsername("user1");
        user.setPassword(SecurityConstants.PASSWORD_ENCODER.encode("password"));
        user.setAuthorities(Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")));
        return new InMemoryUserDetailsManager(user);
    }

}
