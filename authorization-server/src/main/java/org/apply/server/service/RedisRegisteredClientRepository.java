package org.apply.server.service;

import lombok.RequiredArgsConstructor;
import org.apply.server.entity.OAuth2RegisteredClient;
import org.apply.server.repository.OAuth2RegisteredClientRepository;
import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.util.Assert;

@RequiredArgsConstructor
public class RedisRegisteredClientRepository implements RegisteredClientRepository {

	private final OAuth2RegisteredClientRepository registeredClientRepository;

	@Override
	public void save(RegisteredClient registeredClient) {
		Assert.notNull(registeredClient, "registeredClient cannot be null");
		OAuth2RegisteredClient oauth2RegisteredClient = ModelMapper.convertOAuth2RegisteredClient(registeredClient);
		this.registeredClientRepository.save(oauth2RegisteredClient);
	}

	@Nullable
	@Override
	public RegisteredClient findById(String id) {
		Assert.hasText(id, "id cannot be empty");
		return this.registeredClientRepository.findById(id).map(ModelMapper::convertRegisteredClient).orElse(null);
	}

	@Nullable
	@Override
	public RegisteredClient findByClientId(String clientId) {
		Assert.hasText(clientId, "clientId cannot be empty");
		OAuth2RegisteredClient oauth2RegisteredClient = this.registeredClientRepository.findByClientId(clientId);
		return oauth2RegisteredClient != null ? ModelMapper.convertRegisteredClient(oauth2RegisteredClient) : null;
	}

}
