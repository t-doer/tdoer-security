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

import com.tdoer.security.oauth2.OAuth2Constants;
import com.tdoer.security.oauth2.common.AccessTokenThreadLocalHolder;
import com.tdoer.springboot.util.WebUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.security.web.authentication.logout.LogoutHandler;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
/**
 * @author Htinker Hu (htinker@163.com)
 * @create 2017-09-19
 */
public class OAuth2LogoutHandler implements LogoutHandler{
    private Logger logger = LoggerFactory.getLogger(OAuth2LogoutHandler.class);

    private ResourceServerTokenServices tokenServices;

    private CloudResourceRestTemplate restTemplate;

    private CloudOAuth2ClientProperties clientProperties;

    public ResourceServerTokenServices getTokenServices() {
        return tokenServices;
    }

    public void setTokenServices(ResourceServerTokenServices tokenServices) {
        this.tokenServices = tokenServices;
    }

    public CloudResourceRestTemplate getRestTemplate() {
        return restTemplate;
    }

    public void setRestTemplate(CloudResourceRestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    public CloudOAuth2ClientProperties getClientProperties() {
        return clientProperties;
    }

    public void setClientProperties(CloudOAuth2ClientProperties clientProperties) {
        this.clientProperties = clientProperties;
    }

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        try {
            OAuth2AccessToken accessToken = AccessTokenThreadLocalHolder.getAccessToken();

            logger.debug("Found token from request: {}", accessToken);
            if (accessToken != null) {
                try {
                    logger.debug("Revoking token: {}", accessToken);
                    revokeToken(request, (OAuth2Authentication) authentication, accessToken);
                    logger.debug("Revoked token successfully: {}", accessToken);
                } catch (Exception ex) {
                    logger.warn("Failed to revoke token '{}'", accessToken, ex);
                }
            }

            WebUtil.removeValueFromCookie(response, OAuth2Constants.AUTH_TOKEN);
        } catch (Exception ex) {
            logger.warn("Exception occured when to handle logout", ex);
        }
    }

    protected void revokeToken(HttpServletRequest request, OAuth2Authentication authentication, OAuth2AccessToken token){
        restTemplate.delete(clientProperties.getRevokeTokenUri());
    }
}
