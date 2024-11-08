package org.apply.server.controller;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.apply.core.SecurityConstants;
import org.springframework.boot.web.servlet.error.ErrorController;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequiredArgsConstructor
public class DefaultHomeController implements ErrorController {

    @RequestMapping(SecurityConstants.OAUTH_HOME_URI)
    public String home(Authentication authentication, Model model, HttpServletRequest request) {
        User user = (User) authentication.getPrincipal();
        model.addAttribute("user", user);
        return "home";
    }

}
