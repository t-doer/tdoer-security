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
package com.tdoer.security.oauth2.provider.authentication;

import com.tdoer.security.oauth2.OAuth2Constants;
import com.tdoer.security.oauth2.common.AccessTokenThreadLocalHolder;
import com.tdoer.springboot.util.WebUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.token.ConsumerTokenServices;
import org.springframework.security.web.authentication.logout.LogoutHandler;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
/**
 * @author Htinker Hu (htinker@163.com)
 * @create 2017-09-19
 */
public class OAuth2ProviderLogoutHandler implements LogoutHandler{
    private static Logger logger = LoggerFactory.getLogger(OAuth2ProviderLogoutHandler.class);

    private ConsumerTokenServices tokenServices;

    public ConsumerTokenServices getTokenServices() {
        return tokenServices;
    }

    public void setTokenServices(ConsumerTokenServices tokenServices) {
        this.tokenServices = tokenServices;
    }

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        try {
            OAuth2AccessToken accessToken = AccessTokenThreadLocalHolder.getAccessToken();

            logger.info("Found token from logout request [{}]: {}", request.getRequestURL(), accessToken);
            if (accessToken != null) {
                try {
                    logger.info("Revoking token: {}", accessToken);
                    tokenServices.revokeToken(accessToken.getValue());
                    logger.info("Revoked token successfully: {}", accessToken);
                } catch (Exception ex) {
                    logger.info("Failed to revoke token '{}'", accessToken, ex);
                }
            }

            WebUtil.removeValueFromCookie(response, OAuth2Constants.AUTH_TOKEN);
        } catch (Exception ex) {
            logger.warn("Exception occured when to handle logout", ex);
        }
    }
}
