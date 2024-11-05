package org.apply.server.configuration;


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
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.repository.configuration.EnableRedisRepositories;

import java.util.Arrays;

import org.springframework.data.redis.core.convert.RedisCustomConversions;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

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
        return new RedisRegisteredClientRepository(registeredClientRepository);
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
