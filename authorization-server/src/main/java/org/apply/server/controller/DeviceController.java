package org.apply.server.controller;

import lombok.RequiredArgsConstructor;
import org.apply.core.AasConstant;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
@RequiredArgsConstructor
public class DeviceController {

	private final AuthorizationServerSettings authorizationServerSettings;

	@GetMapping(AasConstant.OAUTH_ACTIVATE_URI)
	public String activate(Authentication authentication, Model model,
						   @RequestParam(value = "user_code", required = false) String userCode) {
		String requestUri = authorizationServerSettings.getDeviceVerificationEndpoint();

		if (userCode != null) {
			return "redirect:" + requestUri + "?user_code=" + userCode;
		}

		model.addAttribute("user", authentication.getPrincipal());
		model.addAttribute("requestURI", requestUri);
		return "device-activate";
	}

	@GetMapping(AasConstant.OAUTH_ACTIVATED_URI)
	public String activated() {
		return "device-activated";
	}

	@GetMapping(value = AasConstant.OAUTH_HOME_URI, params = "success")
	public String success() {
		return "device-activated";
	}

}
