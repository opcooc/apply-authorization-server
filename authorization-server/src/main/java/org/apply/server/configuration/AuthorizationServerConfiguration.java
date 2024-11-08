package org.apply.server.configuration;


import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.apply.core.AasConstant;
import org.apply.server.support.jose.Jwks;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.DeviceClientAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.PasswordGrantAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.SmsGrantAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.web.authentication.DeviceClientAuthenticationConverter;
import org.springframework.security.oauth2.server.authorization.web.authentication.PasswordGrantAuthenticationConverter;
import org.springframework.security.oauth2.server.authorization.web.authentication.SmsGrantAuthenticationConverter;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

@Configuration(proxyBeanMethods = false)
public class AuthorizationServerConfiguration {

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http,
                                                                      AuthorizationServerSettings authorizationServerSettings,
                                                                      RegisteredClientRepository registeredClientRepository) throws Exception {

        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        OAuth2AuthorizationServerConfigurer httpConfigurer = http.getConfigurer(OAuth2AuthorizationServerConfigurer.class);

        httpConfigurer.authorizationEndpoint(customizer -> {
            customizer.consentPage(AasConstant.OAUTH_CONSENT_URI);
        });

        httpConfigurer.tokenEndpoint(customizer -> {
            customizer.accessTokenRequestConverter(new PasswordGrantAuthenticationConverter());
            customizer.accessTokenRequestConverter(new SmsGrantAuthenticationConverter());
        });

        httpConfigurer.oidc(Customizer.withDefaults());

        httpConfigurer.deviceAuthorizationEndpoint(customizer -> {
            customizer.verificationUri(AasConstant.OAUTH_ACTIVATE_URI);
        });

        httpConfigurer.deviceVerificationEndpoint(customizer -> {
            customizer.consentPage(AasConstant.OAUTH_CONSENT_URI);
        });

        DeviceClientAuthenticationConverter DeviceClientAuthenticationConverter =
                new DeviceClientAuthenticationConverter(authorizationServerSettings.getDeviceAuthorizationEndpoint());
        DeviceClientAuthenticationProvider DeviceClientAuthenticationProvider =
                new DeviceClientAuthenticationProvider(registeredClientRepository);

        httpConfigurer.clientAuthentication(customizer -> {
            customizer.authenticationConverter(DeviceClientAuthenticationConverter);
            customizer.authenticationProvider(DeviceClientAuthenticationProvider);
        });

        http.exceptionHandling(customizer -> {
            customizer.defaultAuthenticationEntryPointFor(
                    new LoginUrlAuthenticationEntryPoint(AasConstant.OAUTH_LOGIN_URI),
                    new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
            );
        });

        http.oauth2ResourceServer(customizer -> {
            customizer.jwt(Customizer.withDefaults());
        });

        DefaultSecurityFilterChain result = http.build();

        OAuth2TokenGenerator<?> tokenGenerator = http.getSharedObject(OAuth2TokenGenerator.class);
        AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);
        OAuth2AuthorizationService authorizationService = http.getSharedObject(OAuth2AuthorizationService.class);
        SessionRegistry sessionRegistry = http.getSharedObject(SessionRegistry.class);

        PasswordGrantAuthenticationProvider passwordGrantAuthenticationProvider = new PasswordGrantAuthenticationProvider(
                authorizationService, registeredClientRepository, authenticationManager, tokenGenerator
        );
        SmsGrantAuthenticationProvider smsGrantAuthenticationProvider = new SmsGrantAuthenticationProvider(
                authorizationService, registeredClientRepository, authenticationManager, tokenGenerator
        );

        if (sessionRegistry != null) {
            passwordGrantAuthenticationProvider.setSessionRegistry(sessionRegistry);
            smsGrantAuthenticationProvider.setSessionRegistry(sessionRegistry);
        }

        http.authenticationProvider(passwordGrantAuthenticationProvider);
        http.authenticationProvider(smsGrantAuthenticationProvider);

        return result;
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        RSAKey rsaKey = Jwks.generateRsa();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

}
