package org.apply.server.event;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.authentication.event.InteractiveAuthenticationSuccessEvent;
import org.springframework.security.authentication.event.LogoutSuccessEvent;

@Slf4j
public class AuthenticationEventListener {

    @EventListener
    public void onLoginSuccess(AuthenticationSuccessEvent event) {
        log.info("AuthenticationSuccessEvent success.... {}", event.getAuthentication());
    }

    @EventListener
    public void onLoginFailure(AbstractAuthenticationFailureEvent event) {
        log.info("AbstractAuthenticationFailureEvent fail....{}", event.getAuthentication());
    }

    @EventListener
    public void onFormLoginSuccess(InteractiveAuthenticationSuccessEvent event) {
        log.info("InteractiveAuthenticationSuccessEvent success....{}", event.getAuthentication());
    }

    @EventListener
    public void onFormLogoutSuccess(LogoutSuccessEvent event) {
        log.info("LogoutSuccessEvent success....{}", event.getAuthentication());
    }

}
