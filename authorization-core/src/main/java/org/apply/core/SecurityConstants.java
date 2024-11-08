package org.apply.core;

import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

public class SecurityConstants {

    public static final PasswordEncoder PASSWORD_ENCODER = PasswordEncoderFactories.createDelegatingPasswordEncoder();
    public static final AuthorizationGrantType PASSWORD = new AuthorizationGrantType("urn:ietf:params:oauth:grant-type:password");
    public static final AuthorizationGrantType SMS = new AuthorizationGrantType("urn:ietf:params:oauth:grant-type:sms_code");

    public static final String OAUTH_HOME_URI = "/";
    public static final String OAUTH_ERROR_URI = "/error";
    public static final String OAUTH_LOGIN_URI = "/login";
    public static final String OAUTH_CONSENT_URI = "/oauth/consent";
    public static final String OAUTH_ACTIVATE_URI = "/activate";
    public static final String OAUTH_ACTIVATED_URI = "/activated";

    public static final String PRE_CAPTCHA_VERIFY_PARAM = "pcv_id";

    public static final String OAUTH_PARAMETER_NAME_CONTACT = "contact";

    public static final String OAUTH_PARAMETER_NAME_CAPTCHA = "captcha";

    public static final String CAPTCHA_ID_NAME = "captchaId";

    public static final String OAUTH_PARAMETER_NAME_LOGIN_TYPE = "login_type";
    public static final String CONTACT_LOGIN_TYPE = "login_contact";

}
