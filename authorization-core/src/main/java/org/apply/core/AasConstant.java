package org.apply.core;

import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

public class AasConstant {

    public static final PasswordEncoder PASSWORD_ENCODER = PasswordEncoderFactories.createDelegatingPasswordEncoder();

    public static final String LOGIN_PAGE = "/login";
    public static final String OAUTH_CONSENT_URI = "/oauth/consent";
    public static final String HTTP_TENANT_ID = "http_tenant_id";

}
