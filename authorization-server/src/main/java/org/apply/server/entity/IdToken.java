package org.apply.server.entity;

import lombok.Getter;

import java.time.Instant;

@Getter
public class IdToken extends OAuth2AuthorizationGrantAuthorization.AbstractToken {

    private final OAuth2AuthorizationGrantAuthorization.ClaimsHolder claims;

    public IdToken(String tokenValue, Instant issuedAt, Instant expiresAt, boolean invalidated,
                   OAuth2AuthorizationGrantAuthorization.ClaimsHolder claims) {
        super(tokenValue, issuedAt, expiresAt, invalidated);
        this.claims = claims;
    }

}
