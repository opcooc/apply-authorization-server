package org.springframework.security.oauth2.server.authorization.basic;

import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.util.SpringAuthorizationServerVersion;
import org.springframework.util.Assert;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class BasicGrantAuthenticationToken extends AbstractAuthenticationToken {

    private static final long serialVersionUID = SpringAuthorizationServerVersion.SERIAL_VERSION_UID;

    private final AuthorizationGrantType authorizationGrantType;

    private final String clientId;

    private final Map<String, Object> additionalParameters;

    protected BasicGrantAuthenticationToken(AuthorizationGrantType authorizationGrantType,
                                            String clientId, @Nullable Map<String, Object> additionalParameters) {
        super(Collections.emptyList());
        Assert.notNull(authorizationGrantType, "authorizationGrantType cannot be null");
        Assert.notNull(clientId, "clientId cannot be null");
        this.authorizationGrantType = authorizationGrantType;
        this.clientId = clientId;
        this.additionalParameters = Collections.unmodifiableMap(
                (additionalParameters != null) ? new HashMap<>(additionalParameters) : Collections.emptyMap());
    }

    public AuthorizationGrantType getGrantType() {
        return this.authorizationGrantType;
    }

    @Override
    public Object getPrincipal() {
        return this.clientId;
    }

    @Override
    public Object getCredentials() {
        return "";
    }

    public Map<String, Object> getAdditionalParameters() {
        return this.additionalParameters;
    }
}
