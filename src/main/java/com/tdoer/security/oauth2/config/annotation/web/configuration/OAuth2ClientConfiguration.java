/*
 * Copyright 2013-2014 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

package com.tdoer.security.oauth2.config.annotation.web.configuration;

import com.tdoer.security.oauth2.client.token.AccessTokenRequestFactory;
import com.tdoer.security.oauth2.client.token.CloudOAuth2ClientContext;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Scope;
import org.springframework.context.annotation.ScopedProxyMode;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;

/**
 * @author Dave Syer
 * 
 */
@Configuration
public class OAuth2ClientConfiguration {

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
