/*
 * Copyright 2017-2019 T-Doer (tdoer.com).
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.tdoer.security.oauth2.http.converter;

import com.tdoer.security.oauth2.common.exception.OAuth2ExceptionFactory;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.HttpOutputMessage;
import org.springframework.http.MediaType;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.http.converter.HttpMessageNotWritableException;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.http.converter.FormOAuth2ExceptionHttpMessageConverter;
import org.springframework.util.MultiValueMap;

import java.io.IOException;
import java.util.List;
import java.util.Map;
/**
 * @author Htinker Hu (htinker@163.com)
 * @create 2017-09-19
 */
public class DelegatingFormOAuth2ExceptionHttpMessageConverter implements HttpMessageConverter<OAuth2Exception> {
    protected FormOAuth2ExceptionHttpMessageConverter exceptionHttpMessageConverter;
    protected FormHttpMessageConverter delegateMessageConverter;

    public DelegatingFormOAuth2ExceptionHttpMessageConverter(){
        exceptionHttpMessageConverter = new FormOAuth2ExceptionHttpMessageConverter();
        delegateMessageConverter = new FormHttpMessageConverter();
    }

    @Override
    public boolean canRead(Class<?> clazz, MediaType mediaType) {
        return exceptionHttpMessageConverter.canRead(clazz, mediaType);
    }

    @Override
    public boolean canWrite(Class<?> clazz, MediaType mediaType) {
        return exceptionHttpMessageConverter.canWrite(clazz, mediaType);
    }

    @Override
    public List<MediaType> getSupportedMediaTypes() {
        return exceptionHttpMessageConverter.getSupportedMediaTypes();
    }

    @Override
    public OAuth2Exception read(Class<? extends OAuth2Exception> clazz, HttpInputMessage inputMessage) throws IOException, HttpMessageNotReadableException {
        MultiValueMap<String, String> data = delegateMessageConverter.read(null, inputMessage);
        Map<String,String> flattenedData = data.toSingleValueMap();

        return OAuth2ExceptionFactory.newOAuth2Exception(flattenedData);
    }

    @Override
    public void write(OAuth2Exception t, MediaType contentType, HttpOutputMessage outputMessage) throws IOException, HttpMessageNotWritableException {
        exceptionHttpMessageConverter.write(t, contentType, outputMessage);
    }
}
