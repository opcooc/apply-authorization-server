package org.apply.server.entity;

import java.time.Duration;
import java.time.Instant;
import java.util.Set;

import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.redis.core.RedisHash;
import org.springframework.data.redis.core.index.Indexed;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithm;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;

@Data
@RedisHash("oauth2_registered_client")
public class OAuth2RegisteredClient {

	@Id
	private final String id;

	@Indexed
	private final String clientId;

	private final Instant clientIdIssuedAt;

	private final String clientSecret;

	private final Instant clientSecretExpiresAt;

	private final String clientName;

	private final Set<ClientAuthenticationMethod> clientAuthenticationMethods;

	private final Set<AuthorizationGrantType> authorizationGrantTypes;

	private final Set<String> redirectUris;

	private final Set<String> postLogoutRedirectUris;

	private final Set<String> scopes;

	private final ClientSettings clientSettings;

	private final TokenSettings tokenSettings;

	@Data
	public static class ClientSettings {

		private final boolean requireProofKey;

		private final boolean requireAuthorizationConsent;

		private final String jwkSetUrl;

		private final JwsAlgorithm tokenEndpointAuthenticationSigningAlgorithm;

		private final String x509CertificateSubjectDN;

	}

	@Data
	public static class TokenSettings {

		private final Duration authorizationCodeTimeToLive;

		private final Duration accessTokenTimeToLive;

		private final OAuth2TokenFormat accessTokenFormat;

		private final Duration deviceCodeTimeToLive;

		private final boolean reuseRefreshTokens;

		private final Duration refreshTokenTimeToLive;

		private final SignatureAlgorithm idTokenSignatureAlgorithm;

		private final boolean x509CertificateBoundAccessTokens;

	}

}
