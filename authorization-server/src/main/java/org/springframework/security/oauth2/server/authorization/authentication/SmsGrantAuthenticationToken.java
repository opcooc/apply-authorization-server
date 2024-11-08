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
public class SmsGrantAuthenticationToken extends BasicGrantAuthenticationToken {

    private final String phone;
    private final String smsCaptcha;
    private final Set<String> scopes;

    public SmsGrantAuthenticationToken(String phone, String smsCaptcha, Set<String> scopes, String clientId,
                                       @Nullable Map<String, Object> additionalParameters) {
        super(SecurityConstants.SMS, clientId, additionalParameters);
        Assert.hasText(phone, "phone cannot be empty");
        Assert.hasText(smsCaptcha, "smsCaptcha cannot be empty");
        this.phone = phone;
        this.smsCaptcha = smsCaptcha;
        this.scopes = Collections.unmodifiableSet(scopes != null ? new HashSet<>(scopes) : Collections.emptySet());
    }

}