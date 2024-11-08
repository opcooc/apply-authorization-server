package org.springframework.security.oauth2.server.authorization.authentication;

import lombok.Getter;
import org.apply.core.AasConstant;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

@Getter
public class SmsCaptchaGrantAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken {

    private final String phone;
    private final String smsCaptcha;
    private final Set<String> scopes;

    public SmsCaptchaGrantAuthenticationToken(String phone,
                                              String smsCaptcha,
                                              Set<String> scopes,
                                              Authentication clientPrincipal,
                                              @Nullable Map<String, Object> additionalParameters) {
        super(AasConstant.SMS, clientPrincipal, additionalParameters);
        Assert.hasText(phone, "phone cannot be empty");
        Assert.hasText(smsCaptcha, "smsCaptcha cannot be empty");
        this.phone = phone;
        this.smsCaptcha = smsCaptcha;
        this.scopes = Collections.unmodifiableSet(scopes != null ? new HashSet<>(scopes) : Collections.emptySet());
    }

}