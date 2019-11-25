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
import com.tdoer.security.oauth2.common.token.TokenTemplate;
import com.tdoer.security.oauth2.provider.authentication.OAuth2ProviderLogoutHandler;
import com.tdoer.security.oauth2.provider.authentication.RedirectUriAuthenticationFailureHandler;
import com.tdoer.security.oauth2.provider.error.AuthenticationEntryPointDelegator;
import com.tdoer.security.oauth2.provider.error.RedirectUriAuthenticationEntryPoint;
import com.tdoer.security.oauth2.provider.error.ResourceServerOAuth2AuthenticationEntryPoint;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter;
import org.springframework.util.Assert;

import javax.servlet.http.HttpServletRequest;

/**
 * @author Htinker Hu (htinker@163.com)
 * @create 2019-11-11
 */
public class ProviderServiceConfigurer {
    private String loginPage;
    private ApplicationContext applicationContext;
    private CloudOAuth2ClientProperties clientProperties;
    private TokenTemplate tokenTemplate;
    private ResourceServerTokenServices tokenServices;
    private OAuth2ProviderLogoutHandler logoutHandler;
    private AuthenticationSuccessHandler successHandler;
    private AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource;

    public ProviderServiceConfigurer(String loginPage,
                                     ApplicationContext applicationContext) {


        Assert.hasText(loginPage, "Login page is required, cannot be blank");
        Assert.notNull(applicationContext, "ApplicationContext cannot be null");

        this.loginPage = loginPage;
        this.applicationContext = applicationContext;
        this.clientProperties = applicationContext.getBean(CloudOAuth2ClientProperties.class);
        this.tokenTemplate = applicationContext.getBean(TokenTemplate.class);
        this.tokenServices = applicationContext.getBean(ResourceServerTokenServices.class);
        this.logoutHandler = applicationContext.getBean(OAuth2ProviderLogoutHandler.class);
        this.successHandler = applicationContext.getBean(AuthenticationSuccessHandler.class);
        this.authenticationDetailsSource = applicationContext.getBean(AuthenticationDetailsSource.class);

        Assert.notNull(clientProperties, "CloudOAuth2ClientProperties bean in ApplicationContext is required");
        Assert.notNull(tokenTemplate, "AuthorizationCodeTokenTemplate bean in ApplicationContext is required");
        Assert.notNull(tokenServices, "ResourceServerTokenServices bean in ApplicationContext is required");
        Assert.notNull(logoutHandler, "OAuth2LogoutHandler bean in ApplicationContext is required");
        Assert.notNull(successHandler, "AuthenticationSuccessHandler bean in ApplicationContext is required");
        Assert.notNull(authenticationDetailsSource, "AuthenticationDetailsSource bean in ApplicationContext is required");
    }

    public void configure(HttpSecurity http) throws Exception {
        http.addFilterBefore(cloudEnvironmentProcessingFilter(), WebAsyncManagerIntegrationFilter.class);
        http.addFilterBefore(cloudServiceCheckAccessFilter(), SecurityContextPersistenceFilter.class);
        http.addFilterAfter(accessTokenAuthenticationProcessingFilter(), SecurityContextPersistenceFilter.class);

        http
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                // Logout needs to finish 3 steps
                // 1. Clean access token in cookie, in LogoutHandler
                // 2. Ask authorization server to revoke the access token, in LogoutHandler
                // 3. Tell client to sent logout request to "passport"
                .logout().addLogoutHandler(logoutHandler)
                .and()
                .formLogin().authenticationDetailsSource(authenticationDetailsSource)
                .loginPage(loginPage)
                .successHandler(successHandler)
                .failureHandler(new RedirectUriAuthenticationFailureHandler(loginPage + "?error=401"))
                .and()
                // Redirect request to login if authentiation exception
                .exceptionHandling().authenticationEntryPoint(authenticationEntryPoint())
                .and()
                .csrf().disable();
    }

    public AuthenticationEntryPoint authenticationEntryPoint(){
        return new AuthenticationEntryPointDelegator(
                new ResourceServerOAuth2AuthenticationEntryPoint(),
                new RedirectUriAuthenticationEntryPoint(loginPage)
        );
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
