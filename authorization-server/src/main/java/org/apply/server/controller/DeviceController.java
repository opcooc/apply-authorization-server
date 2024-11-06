package org.apply.server.controller;

import lombok.RequiredArgsConstructor;
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

	@GetMapping("/activate")
	public String activate(Authentication authentication, Model model,
						   @RequestParam(value = "user_code", required = false) String userCode) {
		String requestURI = authorizationServerSettings.getDeviceVerificationEndpoint();

		if (userCode != null) {
			return "redirect:" + requestURI + "?user_code=" + userCode;
		}

		model.addAttribute("user", authentication.getPrincipal());
		model.addAttribute("requestURI", requestURI);
		return "device-activate";
	}

	@GetMapping("/activated")
	public String activated() {
		return "device-activated";
	}

	@GetMapping(value = "/", params = "success")
	public String success() {
		return "device-activated";
	}

}
