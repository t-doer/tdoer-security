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
import com.tdoer.security.oauth2.client.CloudOAuth2ClientProperties;
import com.tdoer.security.oauth2.common.AccessTokenThreadLocalHolder;
import com.tdoer.springboot.util.WebUtil;
import org.apache.commons.codec.Charsets;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.*;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
/**
 * @author Htinker Hu (htinker@163.com)
 * @create 2017-09-19
 */
public class OAuth2TokenAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private AuthorizationServerTokenServices tokenServices;

    private ClientDetailsService clientDetailsService;

    private OAuth2RequestFactory requestFactory;

    private CloudOAuth2ClientProperties clientProperties;

    public OAuth2TokenAuthenticationSuccessHandler(CloudOAuth2ClientProperties clientProperties) {
        this.clientProperties = clientProperties;
        setTargetUrlParameter("redirect_uri");
    }

    /**
     * Calls the parent class {@code handle()} method to forward or redirect to the target
     * URL, and then calls {@code clearAuthenticationAttributes()} to remove any leftover
     * session data.
     *
     * @param request
     * @param response
     * @param authentication
     */
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {

        ClientDetails authenticatedClient = clientDetailsService.loadClientByClientId(clientProperties.getClientId());
        OAuth2Request oAuth2Request = createOAuth2Request(authenticatedClient, request);

        OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(oAuth2Request, authentication);

        OAuth2AccessToken accessToken = tokenServices.createAccessToken(oAuth2Authentication);

        // Set to local holder, token services may use it to load authentication
        AccessTokenThreadLocalHolder.setAccessToken(accessToken);

        // set to cookie and header
        WebUtil.addValueIntoResponseHeaderAndCookie(response, request, OAuth2Constants.AUTH_TOKEN, accessToken.getValue());

        super.onAuthenticationSuccess(request, response, authentication);
    }

    /**
     * Builds the target URL according to the logic defined in the main class Javadoc.
     *
     * @param request
     * @param response
     */
    @Override
    protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response) {
        String targetUrlParameter = getTargetUrlParameter();
        String redirectUri = request.getParameter(targetUrlParameter);
        if(!StringUtils.hasText(redirectUri)){
            redirectUri = WebUtil.getRequestParameterFromReferer(request, targetUrlParameter);
            if(redirectUri != null){
                redirectUri = UriUtils.decode(redirectUri, Charsets.UTF_8);
            }
        }

        return redirectUri;
    }

    protected OAuth2Request createOAuth2Request(ClientDetails clientDetails, HttpServletRequest request){
        Map<String, String> parameters = new HashMap<>();
        TokenRequest tokenRequest = requestFactory.createTokenRequest(parameters, clientDetails);
        return requestFactory.createOAuth2Request(clientDetails, tokenRequest);
    }

    public AuthorizationServerTokenServices getTokenServices() {
        return tokenServices;
    }

    public void setTokenServices(AuthorizationServerTokenServices tokenServices) {
        this.tokenServices = tokenServices;
    }

    public ClientDetailsService getClientDetailsService() {
        return clientDetailsService;
    }

    public void setClientDetailsService(ClientDetailsService clientDetailsService) {
        this.clientDetailsService = clientDetailsService;
    }

    public OAuth2RequestFactory getRequestFactory() {
        return requestFactory;
    }

    public void setRequestFactory(OAuth2RequestFactory requestFactory) {
        this.requestFactory = requestFactory;
    }
}
