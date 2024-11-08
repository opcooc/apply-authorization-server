package org.apply.server.entity;

import lombok.Getter;
import org.springframework.data.redis.core.index.Indexed;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

import java.security.Principal;
import java.time.Instant;
import java.util.Set;

@Getter
public class OAuth2AuthorizationPasswordGrantAuthorization extends OAuth2AuthorizationGrantAuthorization {

    private final Principal principal;

    private final OAuth2AuthorizationRequest authorizationRequest;

    public OAuth2AuthorizationPasswordGrantAuthorization(String id, String registeredClientId, String principalName,
                                                         Set<String> authorizedScopes, AccessToken accessToken,
                                                         RefreshToken refreshToken, Principal principal,
                                                         OAuth2AuthorizationRequest authorizationRequest) {
        super(id, registeredClientId, principalName, authorizedScopes, accessToken, refreshToken);
        this.principal = principal;
        this.authorizationRequest = authorizationRequest;
    }

}
