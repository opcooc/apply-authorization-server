package org.apply.server.configuration;

import org.apply.core.AasConstant;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
public class DefaultSecurityConfiguration {

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

        return http.build();
    }

}
