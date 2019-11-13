package com.tdoer.security.oauth2.client.token.grant.implicit;

import com.tdoer.security.oauth2.http.converter.DelegatingFormOAuth2ExceptionHttpMessageConverter;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.security.oauth2.client.token.grant.implicit.ImplicitAccessTokenProvider;
import org.springframework.web.client.RestTemplate;

import java.util.ArrayList;

public class CloudImplicitTokenProvider extends ImplicitAccessTokenProvider {
    public CloudImplicitTokenProvider(RestTemplate restTemplate){

        ArrayList<HttpMessageConverter<?>> messageConverters = new ArrayList<>(restTemplate.getMessageConverters());
        // Add customized converter to read more OAuth2Exception
        messageConverters.add(new DelegatingFormOAuth2ExceptionHttpMessageConverter());

        setMessageConverters(messageConverters);
        setInterceptors(restTemplate.getInterceptors());
        setRequestFactory(restTemplate.getRequestFactory());
    }
}
