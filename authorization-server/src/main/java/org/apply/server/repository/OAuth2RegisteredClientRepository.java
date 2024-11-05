package org.apply.server.repository;

import org.apply.server.entity.OAuth2RegisteredClient;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface OAuth2RegisteredClientRepository extends CrudRepository<OAuth2RegisteredClient, String> {

	OAuth2RegisteredClient findByClientId(String clientId);

}
