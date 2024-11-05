package org.apply.server.convert;

import org.apply.server.entity.OAuth2AuthorizationGrantAuthorization;
import org.apply.server.utils.JsonUtils;
import org.springframework.core.convert.converter.Converter;
import org.springframework.data.convert.WritingConverter;

@WritingConverter
public class ClaimsHolderToBytesConverter implements Converter<OAuth2AuthorizationGrantAuthorization.ClaimsHolder, byte[]> {

	@Override
	public byte[] convert(OAuth2AuthorizationGrantAuthorization.ClaimsHolder value) {
		return JsonUtils.toJsonBytes(value);
	}

}
