package org.springframework.security.oauth2.server.authorization.web.authentication;

import jakarta.servlet.http.HttpServletRequest;
import org.apply.core.AasConstant;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.SmsCaptchaGrantAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class SmsGrantAuthenticationConverter implements AuthenticationConverter {

    @Override
    public Authentication convert(HttpServletRequest request) {

        String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);
        if (!AasConstant.SMS.getValue().equals(grantType)) {
            return null;
        }

        MultiValueMap<String, String> parameters = OAuth2EndpointUtils.getFormParameters(request);

        String scope = parameters.getFirst(OAuth2ParameterNames.SCOPE);
        if (StringUtils.hasText(scope) && parameters.get(OAuth2ParameterNames.SCOPE).size() != 1) {
            OAuth2EndpointUtils.throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.SCOPE,
                    OAuth2EndpointUtils.ACCESS_TOKEN_REQUEST_ERROR_URI);
        }
        Set<String> requestedScopes = null;
        if (StringUtils.hasText(scope)) {
            requestedScopes = new HashSet<>(Arrays.asList(StringUtils.delimitedListToStringArray(scope, " ")));
        }

        String clientId = parameters.getFirst(OAuth2ParameterNames.CLIENT_ID);
        if (!StringUtils.hasText(clientId) || parameters.get(OAuth2ParameterNames.CLIENT_ID).size() != 1) {
            OAuth2EndpointUtils.throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.CLIENT_ID,
                    OAuth2EndpointUtils.ACCESS_TOKEN_REQUEST_ERROR_URI);
        }

        String phone = parameters.getFirst(AasConstant.OAUTH_PARAMETER_NAME_PHONE);
        if (!StringUtils.hasText(phone) || parameters.get(AasConstant.OAUTH_PARAMETER_NAME_PHONE).size() != 1) {
            OAuth2EndpointUtils.throwError(OAuth2ErrorCodes.INVALID_REQUEST, AasConstant.OAUTH_PARAMETER_NAME_PHONE,
                    OAuth2EndpointUtils.ACCESS_TOKEN_REQUEST_ERROR_URI);
        }

        String smsCaptcha = parameters.getFirst(AasConstant.OAUTH_PARAMETER_NAME_SMS_CAPTCHA);
        if (!StringUtils.hasText(smsCaptcha) || parameters.get(AasConstant.OAUTH_PARAMETER_NAME_SMS_CAPTCHA).size() != 1) {
            OAuth2EndpointUtils.throwError(OAuth2ErrorCodes.INVALID_REQUEST, AasConstant.OAUTH_PARAMETER_NAME_SMS_CAPTCHA,
                    OAuth2EndpointUtils.ACCESS_TOKEN_REQUEST_ERROR_URI);
        }

        Map<String, Object> additionalParameters = new HashMap<>();
        parameters.forEach((key, value) -> {
            if (!key.equals(OAuth2ParameterNames.GRANT_TYPE)
                    && !key.equals(AasConstant.OAUTH_PARAMETER_NAME_PHONE)
                    && !key.equals(AasConstant.OAUTH_PARAMETER_NAME_SMS_CAPTCHA)
                    && !key.equals(OAuth2ParameterNames.CLIENT_ID)
                    && !key.equals(OAuth2ParameterNames.SCOPE)) {
                additionalParameters.put(key, (value.size() == 1) ? value.get(0) : value.toArray(new String[0]));
            }
        });

        return new SmsCaptchaGrantAuthenticationToken(phone, smsCaptcha, requestedScopes, clientId, additionalParameters);
    }

}