/*
 * Copyright 2019 T-Doer (tdoer.com).
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
 *
 */
package com.tdoer.security.oauth2.client.token.grant.code;

import com.tdoer.security.oauth2.client.CloudOAuth2ClientProperties;
import com.tdoer.security.oauth2.client.CloudResourceDetailsFactory;
import com.tdoer.security.oauth2.client.token.AccessTokenRequestFactory;
import com.tdoer.security.oauth2.common.token.RefreshableTokenTemplate;
import com.tdoer.security.oauth2.common.token.TokenTemplate;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.util.Assert;
import org.springframework.web.client.RestTemplate;

import javax.servlet.http.HttpServletRequest;
/**
 * @author Htinker Hu (htinker@163.com)
 * @create 2017-09-19
 */
public class AuthorizationCodeTokenTemplate implements RefreshableTokenTemplate {

    protected CloudOAuth2ClientProperties clientProperties;

    protected CloudAuthorizationCodeTokenProvider tokenProvider;

    public AuthorizationCodeTokenTemplate(CloudOAuth2ClientProperties clientProperties, RestTemplate restTemplate){
        Assert.notNull(clientProperties, "ClientProperties cannot be null");
        Assert.notNull(restTemplate, "RestTemplate cannot be null");

        this.clientProperties = clientProperties;
        this.tokenProvider = new CloudAuthorizationCodeTokenProvider(restTemplate);
    }

    @Override
    public OAuth2AccessToken createAccessToken(HttpServletRequest request){
        AuthorizationCodeResourceDetails resourceDetails = CloudResourceDetailsFactory.newAuthorizationCodeResourceDetails(clientProperties);
        AccessTokenRequest accessTokenRequest = AccessTokenRequestFactory.create(request);

        return tokenProvider.obtainAccessToken(resourceDetails, accessTokenRequest);
    }

    @Override
    public OAuth2AccessToken refreshAccessToken(HttpServletRequest request, OAuth2RefreshToken refreshToken){
        AuthorizationCodeResourceDetails resourceDetails = CloudResourceDetailsFactory.newAuthorizationCodeResourceDetails(clientProperties);
        AccessTokenRequest accessTokenRequest = AccessTokenRequestFactory.create(request);
        return tokenProvider.refreshAccessToken(resourceDetails, refreshToken, accessTokenRequest);
    }

    @Override
    public CloudOAuth2ClientProperties getClientProperties() {
        return clientProperties;
    }

    public CloudAuthorizationCodeTokenProvider getTokenProvider() {
        return tokenProvider;
    }
}
