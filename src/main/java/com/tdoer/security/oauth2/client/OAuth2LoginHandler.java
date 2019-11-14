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
package com.tdoer.security.oauth2.client;

import com.tdoer.security.oauth2.OAuth2Constants;
import com.tdoer.security.oauth2.client.token.grant.password.ResourceOwnerPasswordTokenTemplate;
import com.tdoer.security.oauth2.common.AccessTokenThreadLocalHolder;
import com.tdoer.springboot.util.WebUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.util.Assert;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @author Htinker Hu (htinker@163.com)
 * @create 2019-11-14
 */
public class OAuth2LoginHandler {
    protected static Logger logger = LoggerFactory.getLogger(OAuth2LoginHandler.class);

    protected ResourceOwnerPasswordTokenTemplate tokenTemplate;

    protected ResourceServerTokenServices tokenServices;

    public OAuth2LoginHandler(ResourceServerTokenServices tokenServices,
                              ResourceOwnerPasswordTokenTemplate tokenTemplate){
        Assert.notNull(tokenServices, "ResourceServerTokenServices cannot be null");
        Assert.notNull(tokenTemplate, "ResourceOwnerPasswordTokenTemplate cannot be null");

        this.tokenServices = tokenServices;
        this.tokenTemplate = tokenTemplate;
    }

    public void login(HttpServletRequest req, HttpServletResponse rsp, String login, String password) {
        // Obtain token
        logger.info("Obtaining token for user login: {}", login);
        OAuth2AccessToken accessToken = tokenTemplate.obtainAccessToken(req, login, password);
        logger.info("Obtained token for user '{}': {}", login, accessToken);

        // Set for down streaming
        logger.info("Set a new token into response header and cookie: {}", accessToken.getValue());
        AccessTokenThreadLocalHolder.setAccessToken(accessToken);
        WebUtil.addValueIntoResponseHeaderAndCookie(rsp, req, OAuth2Constants.AUTH_TOKEN, accessToken.getValue());

        OAuth2Authentication auth = tokenServices.loadAuthentication(accessToken.getValue());
        logger.info("Loaded OAuth2Authentication from token '{}': {}", accessToken.getValue(), auth);

        SecurityContextHolder.getContext().setAuthentication(auth);
    }
}
