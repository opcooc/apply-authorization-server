package org.apply.server.convert;


import org.apply.server.utils.JsonUtils;
import org.springframework.core.convert.converter.Converter;
import org.springframework.data.convert.WritingConverter;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

@WritingConverter
public class OAuth2AuthorizationRequestToBytesConverter implements Converter<OAuth2AuthorizationRequest, byte[]> {

	@Override
	public byte[] convert(OAuth2AuthorizationRequest value) {
		return JsonUtils.toJsonBytes(value);
	}

}
