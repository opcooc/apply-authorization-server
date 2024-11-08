package org.apply.server.entity;

import java.security.Principal;
import java.time.Instant;
import java.util.Set;

import lombok.Getter;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

@Getter
public class OidcAuthorizationCodeGrantAuthorization extends OAuth2AuthorizationCodeGrantAuthorization {

	private final IdToken idToken;

	public OidcAuthorizationCodeGrantAuthorization(String id, String registeredClientId, String principalName,
			Set<String> authorizedScopes, AccessToken accessToken, RefreshToken refreshToken, Principal principal,
			OAuth2AuthorizationRequest authorizationRequest, AuthorizationCode authorizationCode, String state,
			IdToken idToken) {
		super(id, registeredClientId, principalName, authorizedScopes, accessToken, refreshToken, principal,
				authorizationRequest, authorizationCode, state);
		this.idToken = idToken;
	}

}
