package org.apply.server.controller;

import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.http.HttpServletRequest;
import org.apply.core.SecurityConstants;
import org.springframework.boot.web.servlet.error.ErrorController;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class DefaultErrorController implements ErrorController {

    @RequestMapping(SecurityConstants.OAUTH_ERROR_URI)
    public String handleError(Model model, HttpServletRequest request) {
        String errorMessage = getErrorMessage(request);

		if (errorMessage.startsWith("No static resource")) {
			return "404";
		}

        if (errorMessage.startsWith("[access_denied]")) {
            model.addAttribute("errorTitle", "Access Denied");
            model.addAttribute("errorMessage", "You have denied access.");
        } else {
            model.addAttribute("errorTitle", "Error");
            model.addAttribute("errorMessage", errorMessage);
        }
        return "error";
    }

    private String getErrorMessage(HttpServletRequest request) {
        String errorMessage = (String) request.getAttribute(RequestDispatcher.ERROR_MESSAGE);
        return StringUtils.hasText(errorMessage) ? errorMessage : "";
    }

}
