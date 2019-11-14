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
package com.tdoer.security.oauth2.config.annotation.web.configuration;

import com.tdoer.security.oauth2.client.CloudOAuth2ClientProperties;
import com.tdoer.security.oauth2.client.CloudResourceRestTemplate;
import com.tdoer.security.oauth2.client.OAuth2LoginHandler;
import com.tdoer.security.oauth2.client.OAuth2LogoutHandler;
import com.tdoer.security.oauth2.client.token.AccessTokenRequestFactory;
import com.tdoer.security.oauth2.client.token.CloudOAuth2ClientContext;
import com.tdoer.security.oauth2.client.token.grant.code.AuthorizationCodeTokenTemplate;
import com.tdoer.security.oauth2.client.token.grant.password.ResourceOwnerPasswordTokenTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.cloud.client.loadbalancer.LoadBalanced;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Scope;
import org.springframework.context.annotation.ScopedProxyMode;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.web.client.RestTemplate;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;

/**
 * @author Htinker Hu (htinker@163.com)
 * @create 2019-11-11
 */
@Configuration
public class OAuth2ClientConfiguration {

	@Bean
	@ConfigurationProperties(prefix = "security.oauth2.client")
	public CloudOAuth2ClientProperties clientProperties() {
		return new CloudOAuth2ClientProperties();
	}

	@Bean
	@LoadBalanced
	public RestTemplate restTemplate() {
		return new RestTemplate();
	}

	@Bean
	public AuthorizationCodeTokenTemplate authorizationCodeTokenTemplate(CloudOAuth2ClientProperties clientProperties){
		return new AuthorizationCodeTokenTemplate(clientProperties,	restTemplate());
	}

	@Bean
	public ResourceOwnerPasswordTokenTemplate resourceOwnerPasswordTokenTemplate(CloudOAuth2ClientProperties clientProperties){
		return new ResourceOwnerPasswordTokenTemplate(clientProperties, restTemplate());
	}

	@Bean
	@LoadBalanced
	public CloudResourceRestTemplate remoteResourceRestTemplate(CloudOAuth2ClientProperties clientProperties,
																CloudOAuth2ClientContext clientContext) {
		return new CloudResourceRestTemplate(clientProperties, clientContext);
	}

	@Bean
	public OAuth2LoginHandler loginHandler(ResourceServerTokenServices tokenServices,
										   ResourceOwnerPasswordTokenTemplate tokenTemplate){
		return new OAuth2LoginHandler(tokenServices, tokenTemplate);
	}

	@Bean
	public OAuth2LogoutHandler logoutHandler(CloudOAuth2ClientProperties clientProperties,
											 ResourceServerTokenServices tokenServices,
											 CloudResourceRestTemplate resourceRestTemplate){
		OAuth2LogoutHandler handler = new OAuth2LogoutHandler();
		handler.setClientProperties(clientProperties);
		handler.setRestTemplate(resourceRestTemplate);
		handler.setTokenServices(tokenServices);
		return handler;
	}

	@Bean
	public OAuth2ClientContextFilter oauth2ClientContextFilter() {
		OAuth2ClientContextFilter filter = new OAuth2ClientContextFilter();
		return filter;
	}

	@Bean
	public FilterRegistrationBean<OAuth2ClientContextFilter> oauth2ClientContextFilterFilterRegistrationBean(
			OAuth2ClientContextFilter filter, SecurityProperties security) {
		FilterRegistrationBean<OAuth2ClientContextFilter> registration = new FilterRegistrationBean<>();
		registration.setFilter(filter);
		registration.setOrder(security.getFilter().getOrder() - 10);
		return registration;
	}
    /*
     * Customization:
     *
     * See AccessTokenRequestFactory
     *
     * - Htinker Hu, 2019/7/4
     */
	@Bean
	@Scope(value = "request", proxyMode = ScopedProxyMode.INTERFACES)
	protected AccessTokenRequest accessTokenRequest(HttpServletRequest httpServletRequest) {
	    return AccessTokenRequestFactory.create(httpServletRequest);
	}
	
	@Configuration
	protected static class OAuth2ClientContextConfiguration {
		
		@Resource
		@Qualifier("accessTokenRequest")
		private AccessTokenRequest accessTokenRequest;

		/*
		 * Customization:
		 *
		 * Sessionless Web Application, make OAuth2ClientContext request-based scope with a
		 * customized DefaultOAuth2ClientContext.
		 *
		 * - Htinker Hu, 2019/7/4
		 */
		@Bean
		@Scope(value = "request", proxyMode = ScopedProxyMode.INTERFACES)
		public CloudOAuth2ClientContext oauth2ClientContext() {
			return new CloudOAuth2ClientContext(accessTokenRequest);
		}
		
	}

}
