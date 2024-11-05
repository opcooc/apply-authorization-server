package org.apply.server.configuration;


import org.apply.core.AasConstant;
import org.apply.server.convert.*;
import org.apply.server.repository.OAuth2AuthorizationGrantAuthorizationRepository;
import org.apply.server.repository.OAuth2RegisteredClientRepository;
import org.apply.server.repository.OAuth2UserConsentRepository;
import org.apply.server.service.RedisOAuth2AuthorizationConsentService;
import org.apply.server.service.RedisOAuth2AuthorizationService;
import org.apply.server.service.RedisRegisteredClientRepository;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.data.redis.RedisAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.repository.configuration.EnableRedisRepositories;

import java.util.Arrays;
import java.util.UUID;

import org.springframework.data.redis.core.convert.RedisCustomConversions;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

@Configuration(proxyBeanMethods = false)
@AutoConfigureBefore(value = RedisAutoConfiguration.class)
@EnableRedisRepositories("org.apply.server.repository")
public class RedisConfiguration {

    @Bean
    public RedisTemplate<?, ?> redisTemplate(RedisConnectionFactory redisConnectionFactory) {
        RedisTemplate<byte[], byte[]> redisTemplate = new RedisTemplate<>();
        redisTemplate.setConnectionFactory(redisConnectionFactory);
        return redisTemplate;
    }

    @Bean
    public RedisCustomConversions redisCustomConversions() {
        return new RedisCustomConversions(Arrays.asList(
                new UsernamePasswordAuthenticationTokenToBytesConverter(),
                new BytesToUsernamePasswordAuthenticationTokenConverter(),
                new OAuth2AuthorizationRequestToBytesConverter(),
                new BytesToOAuth2AuthorizationRequestConverter(),
                new ClaimsHolderToBytesConverter(),
                new BytesToClaimsHolderConverter()
        ));
    }

    @Bean
    public RedisRegisteredClientRepository registeredClientRepository(
            OAuth2RegisteredClientRepository registeredClientRepository) {

        RegisteredClient messagingClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("HG1795347877071736834")
                .clientSecret(AasConstant.PASSWORD_ENCODER.encode("0b935bd0f1f3e27090812129a6ff04cf"))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .redirectUri("http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc")
                .redirectUri("http://127.0.0.1:8080/authorized")
                .redirectUri("http://127.0.0.1:8080/index.html")
                .postLogoutRedirectUri("http://127.0.0.1:8080/logged-out")
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .scope("message.read")
                .scope("message.write")
                .scope("user.read")
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
                .build();

        RegisteredClient deviceClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("device-messaging-client")
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.DEVICE_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .scope("message.read")
                .scope("message.write")
                .build();

        RegisteredClient tokenExchangeClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("token-client")
                .clientSecret("{noop}token")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(new AuthorizationGrantType("urn:ietf:params:oauth:grant-type:token-exchange"))
                .scope("message.read")
                .scope("message.write")
                .build();

        RegisteredClient mtlsDemoClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("mtls-demo-client")
                .clientAuthenticationMethod(ClientAuthenticationMethod.TLS_CLIENT_AUTH)
                .clientAuthenticationMethod(ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scope("message.read")
                .scope("message.write")
                .clientSettings(
                        ClientSettings.builder()
                                .x509CertificateSubjectDN("CN=demo-client-sample,OU=Spring Samples,O=Spring,C=US")
                                .jwkSetUrl("http://127.0.0.1:8080/jwks")
                                .build()
                )
                .tokenSettings(
                        TokenSettings.builder()
                                .x509CertificateBoundAccessTokens(true)
                                .build()
                )
                .build();

        // Save registered client's in db as if in-memory
        RedisRegisteredClientRepository redisRegisteredClientRepository = new RedisRegisteredClientRepository(registeredClientRepository);
        redisRegisteredClientRepository.save(messagingClient);
        redisRegisteredClientRepository.save(deviceClient);
        redisRegisteredClientRepository.save(tokenExchangeClient);
        redisRegisteredClientRepository.save(mtlsDemoClient);

        return redisRegisteredClientRepository;
    }

    @Bean
    public RedisOAuth2AuthorizationService authorizationService(RegisteredClientRepository registeredClientRepository,
                                                                OAuth2AuthorizationGrantAuthorizationRepository authorizationGrantAuthorizationRepository) {
        return new RedisOAuth2AuthorizationService(registeredClientRepository,
                authorizationGrantAuthorizationRepository);
    }

    @Bean
    public RedisOAuth2AuthorizationConsentService authorizationConsentService(
            OAuth2UserConsentRepository userConsentRepository) {
        return new RedisOAuth2AuthorizationConsentService(userConsentRepository);
    }

}
