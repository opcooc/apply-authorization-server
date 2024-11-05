package org.apply.server.convert;

import org.apply.server.entity.OAuth2AuthorizationGrantAuthorization;
import org.apply.server.utils.JsonUtils;
import org.springframework.core.convert.converter.Converter;
import org.springframework.data.convert.ReadingConverter;

@ReadingConverter
public class BytesToClaimsHolderConverter implements Converter<byte[], OAuth2AuthorizationGrantAuthorization.ClaimsHolder> {

	@Override
	public OAuth2AuthorizationGrantAuthorization.ClaimsHolder convert(byte[] value) {
		return JsonUtils.fromObject(value, OAuth2AuthorizationGrantAuthorization.ClaimsHolder.class);
	}

}
