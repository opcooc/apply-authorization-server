package org.apply.server.controller;

import org.apply.core.SecurityConstants;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class LoginController {

    @GetMapping(SecurityConstants.OAUTH_LOGIN_URI)
    public String login(Authentication authentication, Model model) {

        if (authentication instanceof UsernamePasswordAuthenticationToken) {
            return "redirect:/";
        }

        return "login";
    }

}
