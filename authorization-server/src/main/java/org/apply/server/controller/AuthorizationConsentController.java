package org.apply.server.controller;

import lombok.RequiredArgsConstructor;
import org.apply.core.AasConstant;
import org.apply.server.entity.BasicScope;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.HashSet;
import java.util.Set;

@Controller
@RequiredArgsConstructor
public class AuthorizationConsentController {

    private final AuthorizationServerSettings authorizationServerSettings;
    private final RegisteredClientRepository registeredClientRepository;

    @GetMapping(value = AasConstant.OAUTH_CONSENT_URI)
    public String consent(Authentication authentication, Model model,
                          @RequestParam(OAuth2ParameterNames.CLIENT_ID) String clientId,
                          @RequestParam(OAuth2ParameterNames.SCOPE) String scope,
                          @RequestParam(OAuth2ParameterNames.STATE) String state,
                          @RequestParam(name = OAuth2ParameterNames.USER_CODE, required = false) String userCode) {

        Set<BasicScope> scopeWithDescriptions = new HashSet<>();
        RegisteredClient registeredClient = this.registeredClientRepository.findByClientId(clientId);

        for (String requestedScope : StringUtils.delimitedListToStringArray(scope, " ")) {
            if (OidcScopes.OPENID.equals(requestedScope)) {
                continue;
            }
            BasicScope basicScope = BasicScope.fromScope(requestedScope);
            if (basicScope == null) {
                throw new RuntimeException("basicScope is null");
            }
            scopeWithDescriptions.add(basicScope);
        }
        model.addAttribute("user", authentication.getPrincipal());
        model.addAttribute("clientId", clientId);
        model.addAttribute("clientName", registeredClient.getClientName());
        model.addAttribute("state", state);
        model.addAttribute("scopes", scopeWithDescriptions);
        model.addAttribute("principalName", authentication.getName());
        model.addAttribute("userCode", userCode);

        String requestUri = StringUtils.hasText(userCode)
                ? authorizationServerSettings.getDeviceVerificationEndpoint()
                : authorizationServerSettings.getAuthorizationEndpoint();
        model.addAttribute("requestURI", requestUri);

        return "consent";
    }

}
