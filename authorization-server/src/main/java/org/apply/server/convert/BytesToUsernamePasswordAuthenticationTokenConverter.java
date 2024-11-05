package org.apply.server.convert;

import org.apply.server.utils.JsonUtils;
import org.springframework.core.convert.converter.Converter;
import org.springframework.data.convert.ReadingConverter;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

@ReadingConverter
public class BytesToUsernamePasswordAuthenticationTokenConverter implements Converter<byte[], UsernamePasswordAuthenticationToken> {

	@Override
	public UsernamePasswordAuthenticationToken convert(byte[] value) {
		return JsonUtils.fromObject(value, UsernamePasswordAuthenticationToken.class);
	}

}
