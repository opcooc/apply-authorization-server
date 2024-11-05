package org.apply.server.entity;

import java.time.Instant;
import java.util.Map;
import java.util.Set;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.redis.core.RedisHash;
import org.springframework.data.redis.core.index.Indexed;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;

@Data
@RedisHash("oauth2_authorization")
public abstract class OAuth2AuthorizationGrantAuthorization {

	@Id
	private final String id;

	private final String registeredClientId;

	private final String principalName;

	private final Set<String> authorizedScopes;

	private final AccessToken accessToken;

	private final RefreshToken refreshToken;

	@Data
	public static class ClaimsHolder {

		private final Map<String, Object> claims;

	}

	@Getter
	protected abstract static class AbstractToken {

		@Indexed
		private final String tokenValue;

		private final Instant issuedAt;

		private final Instant expiresAt;

		private final boolean invalidated;

		protected AbstractToken(String tokenValue, Instant issuedAt, Instant expiresAt, boolean invalidated) {
			this.tokenValue = tokenValue;
			this.issuedAt = issuedAt;
			this.expiresAt = expiresAt;
			this.invalidated = invalidated;
		}
	}

	@Getter
	public static class AccessToken extends AbstractToken {

		private final OAuth2AccessToken.TokenType tokenType;

		private final Set<String> scopes;

		private final OAuth2TokenFormat tokenFormat;

		private final ClaimsHolder claims;

		public AccessToken(String tokenValue, Instant issuedAt, Instant expiresAt, boolean invalidated,
				OAuth2AccessToken.TokenType tokenType, Set<String> scopes, OAuth2TokenFormat tokenFormat,
				ClaimsHolder claims) {
			super(tokenValue, issuedAt, expiresAt, invalidated);
			this.tokenType = tokenType;
			this.scopes = scopes;
			this.tokenFormat = tokenFormat;
			this.claims = claims;
		}
	}

	public static class RefreshToken extends AbstractToken {

		public RefreshToken(String tokenValue, Instant issuedAt, Instant expiresAt, boolean invalidated) {
			super(tokenValue, issuedAt, expiresAt, invalidated);
		}

	}

}
