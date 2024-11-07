package org.apply.server.support.filter;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apply.core.AasConstant;
import org.springframework.core.log.LogMessage;
import org.springframework.http.HttpMethod;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;

import java.io.IOException;

@Slf4j
public class PreCaptchaVerifyFilter implements Filter {

    protected final Log logger = LogFactory.getLog(getClass());

    private static final OrRequestMatcher DEFAULT_ANT_PATH_REQUEST_MATCHER =
            new OrRequestMatcher(
                    AntPathRequestMatcher.antMatcher(HttpMethod.POST, AasConstant.OAUTH_LOGIN_URI)
                    // ....
            );

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        doFilter((HttpServletRequest) request, (HttpServletResponse) response, chain);
    }

    private void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        if (!DEFAULT_ANT_PATH_REQUEST_MATCHER.matches(request)) {
            chain.doFilter(request, response);
            return;
        }
        String pcvId = request.getParameter(AasConstant.PRE_CAPTCHA_VERIFY_PARAM);
        pcvId = (pcvId != null) ? pcvId.trim() : "";

        if (this.logger.isDebugEnabled()) {
            this.logger.debug(LogMessage.format("Captcha verify param value is {%s}", pcvId));
        }

        // verify http pcvId
//        if (b == null || !b) {
//            return;
//        }
        chain.doFilter(request, response);
    }

}
