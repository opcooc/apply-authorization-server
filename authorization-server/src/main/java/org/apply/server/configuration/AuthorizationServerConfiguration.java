package org.apply.server.configuration;


import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.apply.server.jose.Jwks;
import org.apply.core.AasConstant;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

@Configuration(proxyBeanMethods = false)
public class AuthorizationServerConfiguration {

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {

        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        OAuth2AuthorizationServerConfigurer httpConfigurer = http.getConfigurer(OAuth2AuthorizationServerConfigurer.class);

        httpConfigurer.authorizationEndpoint(customizer -> {
            customizer.consentPage(AasConstant.OAUTH_CONSENT_URI);
        });

        httpConfigurer.oidc(Customizer.withDefaults());

        // 设置设备码端点
        httpConfigurer.deviceAuthorizationEndpoint(customizer -> {
            customizer.verificationUri("/activate");
            customizer.deviceAuthorizationResponseHandler(new DeviceAuthorizationSuccessHandler());
        });

        // 设置设备码端点
        httpConfigurer.deviceVerificationEndpoint(customizer -> {
            customizer.consentPage(AasConstant.OAUTH_CONSENT_URI);
        });

        // 设置设备码端点
        DeviceClientAuthenticationConverter deviceClientAuthenticationConverter =
                new DeviceClientAuthenticationConverter(
                        authorizationServerSettings.getDeviceAuthorizationEndpoint());
        DeviceClientAuthenticationProvider deviceClientAuthenticationProvider =
                new DeviceClientAuthenticationProvider(registeredClientRepository);
        httpConfigurer.clientAuthentication(customizer -> {
            String deviceAuthorizationEndpointUri = authorizationServerSettings.isMultipleIssuersAllowed()
                    ? "/**" + authorizationServerSettings.getDeviceAuthorizationEndpoint()
                    : authorizationServerSettings.getDeviceAuthorizationEndpoint();
            customizer.authenticationConverter(new DeviceClientAuthenticationConverter(deviceAuthorizationEndpointUri));
            customizer.authenticationProvider(new DeviceClientAuthenticationProvider(appService));
        });

        http.exceptionHandling(customizer -> {
            customizer.defaultAuthenticationEntryPointFor(
                    new LoginUrlAuthenticationEntryPoint(AasConstant.LOGIN_PAGE),
                    new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
            );
        });

        return http.build();
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
