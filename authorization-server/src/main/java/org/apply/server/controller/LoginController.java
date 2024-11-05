package org.apply.server.controller;

import org.apply.core.AasConstant;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class LoginController {

    @GetMapping("/login")
    public String login(Authentication authentication, Model model,
                        @RequestParam(value = AasConstant.HTTP_TENANT_ID, required = false) String tenantId) {

        if (StringUtils.hasText(tenantId)) {
            model.addAttribute("tenantId", tenantId);
        }

        if (authentication instanceof UsernamePasswordAuthenticationToken) {
            return "redirect:/";
        }

        return "login";
    }

}
