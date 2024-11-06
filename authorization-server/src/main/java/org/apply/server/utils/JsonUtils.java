package org.apply.server.utils;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.json.JsonMapper;
import org.apply.server.convert.ClaimsHolderMixin;
import org.apply.server.entity.OAuth2AuthorizationGrantAuthorization;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationServerJackson2Module;

import java.util.Locale;
import java.util.TimeZone;

public class JsonUtils {

    public static ObjectMapper objectMapper = JsonMapper.builder()
            .defaultLocale(Locale.CHINA)
            .defaultTimeZone(TimeZone.getTimeZone("GMT+8"))
            .disable(SerializationFeature.FAIL_ON_EMPTY_BEANS)
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
            .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
            .visibility(PropertyAccessor.FIELD, JsonAutoDetect.Visibility.ANY)
            .addModules(SecurityJackson2Modules.getModules(JsonUtils.class.getClassLoader()))
            .addModule(new OAuth2AuthorizationServerJackson2Module())
            .addMixIn(OAuth2AuthorizationGrantAuthorization.ClaimsHolder.class, ClaimsHolderMixin.class)
            .build();

    public static String toJsonString(Object data) {
        try {
            return objectMapper.writeValueAsString(data);
        } catch (Exception e) {
            throw new IllegalArgumentException(e);
        }
    }

    public static byte[] toJsonBytes(Object data) {
        try {
            return objectMapper.writeValueAsBytes(data);
        } catch (Exception e) {
            throw new IllegalArgumentException(e);
        }
    }

    public static <T> T fromObject(String data, Class<T> clazz) {
        try {
            return objectMapper.readValue(data, clazz);
        } catch (Exception e) {
            throw new IllegalArgumentException(e);
        }
    }

    public static <T> T fromObject(byte[] data, Class<T> clazz) {
        try {
            return objectMapper.readValue(data, clazz);
        } catch (Exception e) {
            throw new IllegalArgumentException(e);
        }
    }

}
