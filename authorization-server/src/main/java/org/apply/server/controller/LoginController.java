package org.apply.server.controller;

import org.apply.core.AasConstant;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class LoginController {

    @GetMapping("/login")
    public String login(Authentication authentication, Model model) {

        if (authentication instanceof UsernamePasswordAuthenticationToken) {
            return "redirect:/";
        }

        return "login";
    }

}
