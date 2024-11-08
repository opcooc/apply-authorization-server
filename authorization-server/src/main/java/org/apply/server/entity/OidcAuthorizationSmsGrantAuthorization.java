package org.apply.server.entity;

import lombok.Getter;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

import java.security.Principal;
import java.util.Set;

@Getter
public class OidcAuthorizationSmsGrantAuthorization extends OAuth2AuthorizationPasswordGrantAuthorization {

	private final IdToken idToken;

	public OidcAuthorizationSmsGrantAuthorization(String id, String registeredClientId, String principalName,
                                                  Set<String> authorizedScopes, AccessToken accessToken,
                                                  RefreshToken refreshToken, Principal principal,
                                                  OAuth2AuthorizationRequest authorizationRequest,
                                                  IdToken idToken) {
		super(id, registeredClientId, principalName, authorizedScopes, accessToken, refreshToken, principal, authorizationRequest);
		this.idToken = idToken;
	}

}
