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
package com.tdoer.security.configure;

import com.tdoer.bedrock.web.CloudEnvironmentProcessingFilter;
import com.tdoer.bedrock.web.CloudServiceCheckAccessFilter;
import com.tdoer.security.oauth2.client.CloudOAuth2ClientProperties;
import com.tdoer.security.oauth2.client.OAuth2LogoutHandler;
import com.tdoer.security.oauth2.client.filter.AccessTokenAuthenticationProcessingFilter;
import com.tdoer.security.oauth2.client.token.grant.code.AuthorizationCodeTokenTemplate;
import com.tdoer.security.oauth2.provider.error.AuthenticationEntryPointDelegator;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter;
import org.springframework.util.Assert;

/**
 * @author Htinker Hu (htinker@163.com)
 * @create 2019-11-11
 */
public class ClientServiceConfigurer {
    private ApplicationContext applicationContext;
    private CloudOAuth2ClientProperties clientProperties;
    private AuthorizationCodeTokenTemplate tokenTemplate;
    private ResourceServerTokenServices tokenServices;
    private OAuth2LogoutHandler logoutHandler;

    public ClientServiceConfigurer(ApplicationContext applicationContext,
                                   CloudOAuth2ClientProperties clientProperties,
                                   AuthorizationCodeTokenTemplate tokenTemplate,
                                   ResourceServerTokenServices tokenServices) {
        Assert.notNull(applicationContext, "ApplicationContext cannot be null");
        Assert.notNull(clientProperties, "CloudOAuth2ClientProperties cannot be null");
        Assert.notNull(tokenTemplate, "AuthorizationCodeTokenTemplate cannot be null");
        Assert.notNull(tokenServices, "ResourceServerTokenServices cannot be null");
        this.applicationContext = applicationContext;
        this.clientProperties = clientProperties;
        this.tokenTemplate = tokenTemplate;
        this.tokenServices = tokenServices;
        logoutHandler = applicationContext.getBean(OAuth2LogoutHandler.class);
    }

    public void configure(HttpSecurity http) throws Exception {
        http.addFilterBefore(cloudEnvironmentProcessingFilter(), WebAsyncManagerIntegrationFilter.class);
        http.addFilterBefore(cloudServiceCheckAccessFilter(), SecurityContextPersistenceFilter.class);
        http.addFilterAfter(accessTokenAuthenticationProcessingFilter(), SecurityContextPersistenceFilter.class);

        String logoutSuccessUrl =
                "/?" + clientProperties.getAuthLogoutParameter() + "=" + clientProperties.getAuthorizationServerLogoutUri();
        http
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                // Redirect request to login if authentiation exception
                .exceptionHandling()
                .authenticationEntryPoint(new AuthenticationEntryPointDelegator(clientProperties.getLoginPath()))                .and()
                // Logout needs to finish 3 steps
                // 1. Clean access token in cookie, in LogoutHandler
                // 2. Ask authorization server to revoke the access token, in LogoutHandler
                // 3. Tell client to sent logout request to "passport"
                .logout().logoutUrl(clientProperties.getLogoutPath()).logoutSuccessUrl(logoutSuccessUrl).addLogoutHandler(logoutHandler)
                .and()
                // Disable csrf
                .csrf().disable();
    }

    protected CloudEnvironmentProcessingFilter cloudEnvironmentProcessingFilter(){
        CloudEnvironmentProcessingFilter filter = new CloudEnvironmentProcessingFilter();
        return filter;
    }

    protected CloudServiceCheckAccessFilter cloudServiceCheckAccessFilter(){
        CloudServiceCheckAccessFilter filter = new CloudServiceCheckAccessFilter();
        return filter;
    }

    protected AccessTokenAuthenticationProcessingFilter accessTokenAuthenticationProcessingFilter(){
        AccessTokenAuthenticationProcessingFilter filter = new AccessTokenAuthenticationProcessingFilter();
        filter.setLoginURL(clientProperties.getLoginPath());
        filter.setTokenTemplate(tokenTemplate);
        filter.setTokenServices(tokenServices);
        return filter;
    }
}
