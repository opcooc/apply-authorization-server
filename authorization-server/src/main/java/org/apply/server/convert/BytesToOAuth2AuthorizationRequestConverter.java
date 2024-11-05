package org.apply.server.convert;

import org.apply.server.utils.JsonUtils;
import org.springframework.core.convert.converter.Converter;
import org.springframework.data.convert.ReadingConverter;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

@ReadingConverter
public class BytesToOAuth2AuthorizationRequestConverter implements Converter<byte[], OAuth2AuthorizationRequest> {

    @Override
    public OAuth2AuthorizationRequest convert(byte[] value) {
        return JsonUtils.fromObject(value, OAuth2AuthorizationRequest.class);
    }

}
