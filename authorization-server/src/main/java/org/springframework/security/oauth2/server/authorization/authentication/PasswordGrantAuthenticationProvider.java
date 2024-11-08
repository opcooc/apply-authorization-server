package org.springframework.security.oauth2.server.authorization.authentication;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apply.core.AasConstant;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import java.security.Principal;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
public final class PasswordGrantAuthenticationProvider implements AuthenticationProvider {

    private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";

    private final AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = new WebAuthenticationDetailsSource();

    private final Log logger = LogFactory.getLog(getClass());

    private final OAuth2AuthorizationService authorizationService;

    private final OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;

    private final RegisteredClientRepository registeredClientRepository;

    private final AuthenticationManager authenticationManager;

    public PasswordGrantAuthenticationProvider(OAuth2AuthorizationService authorizationService,
                                               RegisteredClientRepository registeredClientRepository,
                                               AuthenticationManager authenticationManager,
                                               OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator) {
        Assert.notNull(authorizationService, "authorizationService cannot be null");
        Assert.notNull(registeredClientRepository, "registeredClientRepository cannot be null");
        Assert.notNull(authenticationManager, "authenticationManager cannot be null");
        Assert.notNull(tokenGenerator, "tokenGenerator cannot be null");
        this.authorizationService = authorizationService;
        this.registeredClientRepository = registeredClientRepository;
        this.authenticationManager = authenticationManager;
        this.tokenGenerator = tokenGenerator;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        PasswordGrantAuthenticationToken passwordAuthenticationToken = (PasswordGrantAuthenticationToken) authentication;

        String clientId = passwordAuthenticationToken.getPrincipal().toString();
        RegisteredClient registeredClient = this.registeredClientRepository.findByClientId(clientId);
        if (registeredClient == null) {
            OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT,
                    "Device client authentication failed: " + OAuth2ParameterNames.CLIENT_ID, ERROR_URI
            );
            throw new OAuth2AuthenticationException(error);
        }

        if (!registeredClient.getAuthorizationGrantTypes().contains(AasConstant.PASSWORD)) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
        }

        if (this.logger.isTraceEnabled()) {
            this.logger.trace("Retrieved registered client");
        }

        Set<String> authorizedScopes = registeredClient.getScopes();
        if (!CollectionUtils.isEmpty(passwordAuthenticationToken.getScopes())) {
            Set<String> unauthorizedScopes = passwordAuthenticationToken.getScopes().stream()
                    .filter(requestedScope -> !registeredClient.getScopes().contains(requestedScope))
                    .collect(Collectors.toSet());
            if (!CollectionUtils.isEmpty(unauthorizedScopes)) {
                OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST, "OAuth 2.0 Parameter: " + OAuth2ParameterNames.SCOPE, ERROR_URI);
                throw new OAuth2AuthenticationException(error);
            }

            authorizedScopes = new LinkedHashSet<>(passwordAuthenticationToken.getScopes());
        }

        if (this.logger.isTraceEnabled()) {
            this.logger.trace("Validated token request parameters");
        }

        HttpServletRequest request = SecurityUtils.getHttpServletRequest();
        UsernamePasswordAuthenticationToken authRequest = UsernamePasswordAuthenticationToken
                .unauthenticated(passwordAuthenticationToken.getUsername(), passwordAuthenticationToken.getPassword());
        // 添加请求信息
        authRequest.setDetails(this.authenticationDetailsSource.buildDetails(request));
        Authentication principal;
        try {
            principal = authenticationManager.authenticate(authRequest);
        } catch (Exception e) {
            OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST, "Username password authentication error.", ERROR_URI);
            throw new OAuth2AuthenticationException(error);
        }

        DefaultOAuth2TokenContext.Builder tokenContextBuilder = DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .principal(principal)
                .authorizationServerContext(AuthorizationServerContextHolder.getContext())
                .authorizedScopes(authorizedScopes)
                .authorizationGrantType(passwordAuthenticationToken.getGrantType())
                .authorizationGrant(passwordAuthenticationToken);

        OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.withRegisteredClient(registeredClient)
                // 存入授权scope
                .authorizedScopes(authorizedScopes)
                // 当前授权用户名称
                .principalName(principal.getName())
                // 设置当前用户认证信息
                .attribute(Principal.class.getName(), principal)
                .authorizationGrantType(passwordAuthenticationToken.getGrantType());

        // ----- Access token -----
        OAuth2TokenContext tokenContext = tokenContextBuilder.tokenType(OAuth2TokenType.ACCESS_TOKEN).build();
        OAuth2Token generatedAccessToken = this.tokenGenerator.generate(tokenContext);
        if (generatedAccessToken == null) {
            OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
                    "The token generator failed to generate the access token.", ERROR_URI);
            throw new OAuth2AuthenticationException(error);
        }

        if (this.logger.isTraceEnabled()) {
            this.logger.trace("Generated access token");
        }

        OAuth2AccessToken accessToken = OAuth2AuthenticationProviderUtils.accessToken(authorizationBuilder,
                generatedAccessToken, tokenContext);

        // ----- Refresh token -----
        OAuth2RefreshToken refreshToken = null;
        // Do not issue refresh token to public client
        if (registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN)) {
            tokenContext = tokenContextBuilder.tokenType(OAuth2TokenType.REFRESH_TOKEN).build();
            OAuth2Token generatedRefreshToken = this.tokenGenerator.generate(tokenContext);
            if (generatedRefreshToken != null) {
                if (!(generatedRefreshToken instanceof OAuth2RefreshToken)) {
                    OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
                            "The token generator failed to generate a valid refresh token.", ERROR_URI);
                    throw new OAuth2AuthenticationException(error);
                }

                if (this.logger.isTraceEnabled()) {
                    this.logger.trace("Generated refresh token");
                }

                refreshToken = (OAuth2RefreshToken) generatedRefreshToken;
                authorizationBuilder.refreshToken(refreshToken);
            }
        }

        OAuth2Authorization authorization = authorizationBuilder.build();

        this.authorizationService.save(authorization);

        if (this.logger.isTraceEnabled()) {
            this.logger.trace("Saved authorization");
        }

        OAuth2ClientAuthenticationToken clientPrincipal =
                new OAuth2ClientAuthenticationToken(clientId, ClientAuthenticationMethod.NONE, null, null);

        if (this.logger.isTraceEnabled()) {
            this.logger.trace("Authenticated token request");
        }

        return new OAuth2AccessTokenAuthenticationToken(registeredClient, clientPrincipal, accessToken, refreshToken,
                passwordAuthenticationToken.getAdditionalParameters());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return PasswordGrantAuthenticationToken.class.isAssignableFrom(authentication);
    }

}

