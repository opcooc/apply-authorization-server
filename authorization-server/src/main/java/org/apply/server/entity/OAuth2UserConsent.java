package org.apply.server.entity;

import java.util.Set;

import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.redis.core.RedisHash;
import org.springframework.data.redis.core.index.Indexed;
import org.springframework.security.core.GrantedAuthority;

@Data
@RedisHash("oauth2_authorization_consent")
public class OAuth2UserConsent {

	@Id
	private final String id;

	@Indexed
	private final String registeredClientId;

	@Indexed
	private final String principalName;

	private final Set<GrantedAuthority> authorities;

}
