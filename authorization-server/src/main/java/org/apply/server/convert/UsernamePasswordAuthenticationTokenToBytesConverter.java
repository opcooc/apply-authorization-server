package org.apply.server.convert;

import org.apply.server.utils.JsonUtils;
import org.springframework.core.convert.converter.Converter;
import org.springframework.data.convert.WritingConverter;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

@WritingConverter
public class UsernamePasswordAuthenticationTokenToBytesConverter implements Converter<UsernamePasswordAuthenticationToken, byte[]> {

    @Override
    public byte[] convert(UsernamePasswordAuthenticationToken value) {
        return JsonUtils.toJsonBytes(value);
    }

}
