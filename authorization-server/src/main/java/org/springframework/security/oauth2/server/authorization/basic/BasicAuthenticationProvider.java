package org.springframework.security.oauth2.server.authorization.basic;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.apply.core.RedisConstants;
import org.apply.core.SecurityConstants;
import org.apply.core.exception.InvalidCaptchaException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.data.redis.core.script.RedisScript;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.ObjectUtils;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.Collections;
import java.util.Objects;

@Slf4j
public class BasicAuthenticationProvider extends DaoAuthenticationProvider {
    public static final RedisScript<String> SCRIPT_GET_CACHE =
            new DefaultRedisScript<>("local res = redis.call('get',KEYS[1])  if res == nil  then return nil  else  redis.call('del',KEYS[1]) return res end", String.class);

    private final StringRedisTemplate redisTemplate;

    public BasicAuthenticationProvider(UserDetailsService userDetailsService, PasswordEncoder passwordEncoder, StringRedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
        super.setPasswordEncoder(passwordEncoder);
        super.setUserDetailsService(userDetailsService);
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        RequestAttributes requestAttributes = RequestContextHolder.getRequestAttributes();
        if (requestAttributes == null) {
            throw new InvalidCaptchaException("Failed to get the current request.");
        }
        HttpServletRequest request = ((ServletRequestAttributes) requestAttributes).getRequest();

        String loginType = request.getParameter(SecurityConstants.OAUTH_PARAMETER_NAME_LOGIN_TYPE);
        String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);

        if (Objects.equals(loginType, SecurityConstants.CONTACT_LOGIN_TYPE) || Objects.equals(grantType, SecurityConstants.SMS.getValue())) {
            String captcha = request.getParameter(SecurityConstants.OAUTH_PARAMETER_NAME_CAPTCHA);
            if (ObjectUtils.isEmpty(captcha)) {
                throw new InvalidCaptchaException("The captcha cannot be empty.");
            }

            String captchaId = request.getParameter(SecurityConstants.CAPTCHA_ID_NAME);
            String cacheCaptcha = redisTemplate.execute(SCRIPT_GET_CACHE, Collections.singletonList(RedisConstants.IMAGE_CAPTCHA_PREFIX_KEY + captchaId));

            if (!ObjectUtils.isEmpty(cacheCaptcha)) {
                if (!cacheCaptcha.equalsIgnoreCase(captcha)) {
                    throw new InvalidCaptchaException("The captcha is incorrect.");
                }
            } else {
                throw new InvalidCaptchaException("The captcha is abnormal. Obtain it again.");
            }
        }

        return super.authenticate(authentication);
    }


    @Override
    protected void additionalAuthenticationChecks(UserDetails userDetails, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {

        RequestAttributes requestAttributes = RequestContextHolder.getRequestAttributes();
        if (requestAttributes == null) {
            throw new InvalidCaptchaException("Failed to get the current request.");
        }
        HttpServletRequest request = ((ServletRequestAttributes) requestAttributes).getRequest();

        String loginType = request.getParameter(SecurityConstants.OAUTH_PARAMETER_NAME_LOGIN_TYPE);
        String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);

        if (Objects.equals(loginType, SecurityConstants.CONTACT_LOGIN_TYPE) || Objects.equals(grantType, SecurityConstants.SMS.getValue())) {
            return;
        }

        super.additionalAuthenticationChecks(userDetails, authentication);
    }
}