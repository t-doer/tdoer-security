/*
 * Copyright 2010-2012 the original author or authors.
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

package com.tdoer.security.oauth2.client.filter;

import com.tdoer.security.oauth2.OAuth2Constants;
import com.tdoer.security.oauth2.client.token.grant.code.AuthorizationCodeTokenTemplate;
import com.tdoer.security.oauth2.common.AccessTokenThreadLocalHolder;
import com.tdoer.security.oauth2.provider.authentication.CloudOAuth2AuthenticationDetailsSource;
import com.tdoer.springboot.util.WebUtil;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.filter.OAuth2AuthenticationFailureEvent;
import org.springframework.security.oauth2.client.http.AccessTokenRequiredException;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * An OAuth2 client filter that can be used to acquire an OAuth2 access token from an authorization server, and load an
 * authentication object into the SecurityContext.
 *
 * The filter will interspect "login" request
 * 
 * @author Vidya Valmikinathan
 * 
 */
public class OAuth2ClientAuthenticationProcessingFilter extends AbstractAuthenticationProcessingFilter {

	public AuthorizationCodeTokenTemplate tokenTemplate;

	private ResourceServerTokenServices tokenServices;

	private AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource =
			new CloudOAuth2AuthenticationDetailsSource();

	private ApplicationEventPublisher eventPublisher;

	public OAuth2ClientAuthenticationProcessingFilter(String defaultFilterProcessesUrl) {
		super(defaultFilterProcessesUrl);
		setAuthenticationManager(new NoopAuthenticationManager());
		setAuthenticationDetailsSource(authenticationDetailsSource);
	}

	public OAuth2ClientAuthenticationProcessingFilter(RequestMatcher requestMatcher){
		super(requestMatcher);
		setAuthenticationManager(new NoopAuthenticationManager());
		setAuthenticationDetailsSource(authenticationDetailsSource);
	}

	/**
	 * Reference to a CheckTokenServices that can validate an OAuth2AccessToken
	 * 
	 * @param tokenServices
	 */
	public void setTokenServices(ResourceServerTokenServices tokenServices) {
		this.tokenServices = tokenServices;
	}

	/**
	 * A rest template to be used to obtain an access token.
	 * 
	 * @param restTemplate a rest template
	 */
	public void setTokenTemplate(AuthorizationCodeTokenTemplate restTemplate) {
		this.tokenTemplate = restTemplate;
	}
	
	@Override
	public void setApplicationEventPublisher(ApplicationEventPublisher eventPublisher) {
		this.eventPublisher = eventPublisher;
		super.setApplicationEventPublisher(eventPublisher);
	}

	@Override
	public void afterPropertiesSet() {
		Assert.notNull(tokenTemplate, "AuthorizationCodeTokenTemplate is required");
		Assert.notNull(tokenServices, "ResourceServerTokenServices is required");

		super.afterPropertiesSet();
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException, IOException, ServletException {

		OAuth2AccessToken accessToken;
		try {
			accessToken = tokenTemplate.createAccessToken(request);

		} catch (OAuth2Exception e) {
			BadCredentialsException bad = new BadCredentialsException("Could not obtain access token", e);
			publish(new OAuth2AuthenticationFailureEvent(bad));
			throw bad;			
		}
		try {
            // Set to local holder, token services may use it to load authentication
            AccessTokenThreadLocalHolder.setAccessToken(accessToken);

			OAuth2Authentication result = tokenServices.loadAuthentication(accessToken.getValue());
			if (authenticationDetailsSource!=null) {
				request.setAttribute(OAuth2AuthenticationDetails.ACCESS_TOKEN_VALUE, accessToken.getValue());
				request.setAttribute(OAuth2AuthenticationDetails.ACCESS_TOKEN_TYPE, accessToken.getTokenType());
				result.setDetails(authenticationDetailsSource.buildDetails(request));
			}

            // set to cookie and header
            WebUtil.addValueIntoResponseHeaderAndCookie(response, request, OAuth2Constants.AUTH_TOKEN, accessToken.getValue());

            // Keep access token for down streaming
            AccessTokenThreadLocalHolder.setRefreshedMark(true);

            publish(new AuthenticationSuccessEvent(result));

			return result;
		}
		catch (InvalidTokenException e) {
			BadCredentialsException bad = new BadCredentialsException("Could not obtain user details from token", e);
			publish(new OAuth2AuthenticationFailureEvent(bad));
			throw bad;			
		}

	}

	private void publish(ApplicationEvent event) {
		if (eventPublisher!=null) {
			eventPublisher.publishEvent(event);
		}
	}
	
	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
			FilterChain chain, Authentication authResult) throws IOException, ServletException {
		super.successfulAuthentication(request, response, chain, authResult);
	}

	@Override
	protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException failed) throws IOException, ServletException {
		if (failed instanceof AccessTokenRequiredException) {
			// Need to force a redirect via the OAuth client filter, so rethrow here
			throw failed;
		}
		else {
			// If the exception is not a Spring Security exception this will result in a default error page
			super.unsuccessfulAuthentication(request, response, failed);
		}
	}
	
	private static class NoopAuthenticationManager implements AuthenticationManager {

		@Override
		public Authentication authenticate(Authentication authentication)
				throws AuthenticationException {
			throw new UnsupportedOperationException("No authentication should be done with this AuthenticationManager");
		}
		
	}

}