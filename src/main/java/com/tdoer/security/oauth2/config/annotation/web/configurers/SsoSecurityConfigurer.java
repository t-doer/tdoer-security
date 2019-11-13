/*
 * Copyright 2012-2016 the original author or authors.
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

package com.tdoer.security.oauth2.config.annotation.web.configurers;

import com.tdoer.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import com.tdoer.security.oauth2.client.token.grant.code.AuthorizationCodeTokenTemplate;
import com.tdoer.security.oauth2.provider.authentication.CloudOAuth2AuthenticationDetailsSource;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.security.web.util.matcher.RequestHeaderRequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.accept.ContentNegotiationStrategy;
import org.springframework.web.accept.HeaderContentNegotiationStrategy;

import java.util.Collections;

/**
 * Configurer for OAuth2 Single Sign On (SSO).
 *
 * @author Dave Syer
 */
public class SsoSecurityConfigurer {

	private ApplicationContext applicationContext;
	private AuthorizationCodeTokenTemplate tokenTemplate;

	public SsoSecurityConfigurer(ApplicationContext applicationContext, AuthorizationCodeTokenTemplate tokenTemplate) {
        Assert.notNull(applicationContext, "ApplicationContext cannot be null");
        Assert.notNull(tokenTemplate, "AuthorizationCodeTokenTemplate cannot be null");
		this.applicationContext = applicationContext;
		this.tokenTemplate = tokenTemplate;
	}

	public void configure(HttpSecurity http) throws Exception {
		// Delay the processing of the filter until we know the
		// SessionAuthenticationStrategy is available:
		http.apply(new OAuth2ClientAuthenticationConfigurer(oauth2SsoFilter()));
		addAuthenticationEntryPoint(http);
	}

	private void addAuthenticationEntryPoint(HttpSecurity http)
			throws Exception {
		ExceptionHandlingConfigurer<HttpSecurity> exceptions = http.exceptionHandling();
		ContentNegotiationStrategy contentNegotiationStrategy = http
				.getSharedObject(ContentNegotiationStrategy.class);
		if (contentNegotiationStrategy == null) {
			contentNegotiationStrategy = new HeaderContentNegotiationStrategy();
		}
		MediaTypeRequestMatcher preferredMatcher = new MediaTypeRequestMatcher(
				contentNegotiationStrategy, MediaType.APPLICATION_XHTML_XML,
				new MediaType("image", "*"), MediaType.TEXT_HTML, MediaType.TEXT_PLAIN);
		preferredMatcher.setIgnoredMediaTypes(Collections.singleton(MediaType.ALL));
		exceptions.defaultAuthenticationEntryPointFor(
				new LoginUrlAuthenticationEntryPoint(tokenTemplate.getClientProperties().getLoginPath()),
				preferredMatcher);
		// When multiple entry points are provided the default is the first one
		exceptions.defaultAuthenticationEntryPointFor(
				new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED),
				new RequestHeaderRequestMatcher("X-Requested-With", "XMLHttpRequest"));
	}

	private OAuth2ClientAuthenticationProcessingFilter oauth2SsoFilter() {

        ResourceServerTokenServices tokenServices = this.applicationContext
				.getBean(ResourceServerTokenServices.class);

		SimpleUrlAuthenticationSuccessHandler successHandler = new SimpleUrlAuthenticationSuccessHandler();
		successHandler.setTargetUrlParameter(tokenTemplate.getClientProperties().getTargetUrlParameter());
        OAuth2ClientAuthenticationProcessingFilter filter = new OAuth2ClientAuthenticationProcessingFilter(
				tokenTemplate.getClientProperties().getLoginPath());
		filter.setTokenTemplate(tokenTemplate);
		filter.setTokenServices(tokenServices);
		filter.setApplicationEventPublisher(this.applicationContext);
		filter.setAuthenticationSuccessHandler(successHandler);
		filter.setAuthenticationDetailsSource(new CloudOAuth2AuthenticationDetailsSource());
		return filter;
	}

	private static class OAuth2ClientAuthenticationConfigurer
			extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {

		private OAuth2ClientAuthenticationProcessingFilter filter;

		OAuth2ClientAuthenticationConfigurer(
				OAuth2ClientAuthenticationProcessingFilter filter) {
			this.filter = filter;
		}

		@Override
		public void configure(HttpSecurity builder) throws Exception {
			OAuth2ClientAuthenticationProcessingFilter ssoFilter = this.filter;
			ssoFilter.setSessionAuthenticationStrategy(
					builder.getSharedObject(SessionAuthenticationStrategy.class));
			builder.addFilterAfter(ssoFilter,
					AbstractPreAuthenticatedProcessingFilter.class);
		}

	}

}
