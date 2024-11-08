package org.springframework.security.oauth2.server.authorization.authentication;

import lombok.Getter;
import org.apply.core.SecurityConstants;
import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.server.authorization.basic.BasicGrantAuthenticationToken;
import org.springframework.util.Assert;

import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

@Getter
public class PasswordGrantAuthenticationToken extends BasicGrantAuthenticationToken {

    private final String username;
    private String password;
    private final Set<String> scopes;

    public PasswordGrantAuthenticationToken(String username, String password, Set<String> scopes, String clientId,
                                            @Nullable Map<String, Object> additionalParameters) {
        super(SecurityConstants.PASSWORD, clientId, additionalParameters);
        Assert.hasText(username, "username cannot be empty");
        Assert.hasText(password, "password cannot be empty");
        this.username = username;
        this.password = password;
        this.scopes = Collections.unmodifiableSet(scopes != null ? new HashSet<>(scopes) : Collections.emptySet());
    }

    @Override
    public void eraseCredentials() {
        super.eraseCredentials();
        this.password = null;
    }
}
