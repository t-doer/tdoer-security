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
package com.tdoer.security.oauth2.provider.token;

import com.tdoer.bedrock.Platform;
import com.tdoer.bedrock.tenant.TenantClient;
import com.tdoer.security.oauth2.client.CloudOAuth2ClientProperties;
import com.tdoer.security.oauth2.common.token.RefreshableTokenTemplate;
import com.tdoer.security.oauth2.provider.CloudClientDetails;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.util.Assert;

import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;

/**
 * @author Htinker Hu (htinker@163.com)
 * @create 2019-11-17
 */
public class ProviderTokenTemplate implements RefreshableTokenTemplate {

    protected CloudOAuth2ClientProperties clientProperties;

    private OAuth2RequestFactory requestFactory;

    protected TokenGranter tokenGranter;

    public ProviderTokenTemplate(CloudOAuth2ClientProperties clientProperties, OAuth2RequestFactory requestFactory,
                                 TokenGranter tokenGranter) {
        Assert.notNull(clientProperties, "CloudOAuth2ClientProperties cannot be null");
        Assert.notNull(requestFactory, "OAuth2RequestFactory cannot be null");
        Assert.notNull(tokenGranter, "TokenGranter cannot be null");

        this.clientProperties = clientProperties;
        this.requestFactory = requestFactory;
        this.tokenGranter = tokenGranter;
    }

    @Override
    public OAuth2AccessToken refreshAccessToken(HttpServletRequest request, OAuth2RefreshToken refreshToken) {

        TenantClient client = Platform.getCurrentEnvironment().getTenantClient();
        CloudClientDetails clientDetails = new CloudClientDetails(client);

        Map<String, String> parameters = new HashMap<>();
        parameters.put("grant_type", "refresh_token");
        parameters.put("refresh_token", refreshToken.getValue());

        TokenRequest tokenRequest = requestFactory.createTokenRequest(parameters, clientDetails);
        OAuth2AccessToken accessToken = tokenGranter.grant("refresh_token", tokenRequest);

        return accessToken;
    }


    @Override
    public OAuth2AccessToken createAccessToken(HttpServletRequest request) {
        throw new UnsupportedOperationException();
    }

    @Override
    public CloudOAuth2ClientProperties getClientProperties() {
        return clientProperties;
    }
}
