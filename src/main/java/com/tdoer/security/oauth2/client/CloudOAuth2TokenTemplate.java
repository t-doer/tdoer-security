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
package com.tdoer.security.oauth2.client;

import com.tdoer.security.oauth2.client.token.AccessTokenRequestFactory;
import com.tdoer.security.oauth2.client.token.CloudAccessTokenProviderChain;
import com.tdoer.security.oauth2.client.token.grant.client.CloudClientCredentialsTokenProvider;
import com.tdoer.security.oauth2.client.token.grant.code.CloudAuthorizationCodeTokenProvider;
import com.tdoer.security.oauth2.client.token.grant.implicit.CloudImplicitTokenProvider;
import com.tdoer.security.oauth2.client.token.grant.password.CloudUserPasswordTokenProvider;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.oauth2.client.resource.OAuth2AccessDeniedException;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.resource.UserRedirectRequiredException;
import org.springframework.security.oauth2.client.token.AccessTokenProvider;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordResourceDetails;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.util.Assert;
import org.springframework.web.client.RestTemplate;

import javax.servlet.http.HttpServletRequest;
import java.util.Arrays;
/**
 * The token template is used to obtain and refresh access token.
 *
 * @author Htinker Hu (htinker@163.com)
 * @create 2017-09-19
 */
public class CloudOAuth2TokenTemplate {

    protected AccessTokenProvider accessTokenProvider;

    public CloudOAuth2TokenTemplate(RestTemplate restTemplate){
        accessTokenProvider = new CloudAccessTokenProviderChain(Arrays.<AccessTokenProvider> asList(
                new CloudAuthorizationCodeTokenProvider(restTemplate), new CloudImplicitTokenProvider(restTemplate),
                new CloudUserPasswordTokenProvider(restTemplate), new CloudClientCredentialsTokenProvider(restTemplate)));
    }

    /**
     * Only {@link AuthorizationCodeResourceDetails} or {@link ResourceOwnerPasswordResourceDetails}
     * can be used to request refreshing access token.
     *
     * @param resource Must be  {@link AuthorizationCodeResourceDetails} or {@link ResourceOwnerPasswordResourceDetails}
     * @param refreshToken Valid refresh token
     * @param request Http request
     * @return a new access token if successful
     * @throws UserRedirectRequiredException if failed
     */
    public OAuth2AccessToken refreshAccessToken(OAuth2ProtectedResourceDetails resource,
                                                OAuth2RefreshToken refreshToken, HttpServletRequest request) throws UserRedirectRequiredException {
        Assert.isTrue(resource instanceof AuthorizationCodeResourceDetails
                || resource instanceof ResourceOwnerPasswordResourceDetails, "Only AuthorizationCodeResourceDetails" +
                "or ResourceOwnerPasswordResourceDetails can be used to refresh access token");

        AccessTokenRequest accessTokenRequest = AccessTokenRequestFactory.create(request);
        return accessTokenProvider.refreshAccessToken(resource, refreshToken, accessTokenRequest);
    }

    /**
     * Obtain an access token from authorization server according to the given resource details.
     *
     * @param details Resource details, cannot be <code>null</code>
     * @param request Http servlet request, cannot be <code>null</code>
     * @return Access token if successful
     * @throws UserRedirectRequiredException if failed. The exception will be caught by {@link OAuth2ClientContextFilter}
     * @throws AccessDeniedException
     * @throws OAuth2AccessDeniedException
     */
    public OAuth2AccessToken obtainAccessToken(OAuth2ProtectedResourceDetails details, HttpServletRequest request)
            throws UserRedirectRequiredException, AccessDeniedException, OAuth2AccessDeniedException {
        AccessTokenRequest accessTokenRequest = AccessTokenRequestFactory.create(request);
        return accessTokenProvider.obtainAccessToken(details, accessTokenRequest);

    }
}
