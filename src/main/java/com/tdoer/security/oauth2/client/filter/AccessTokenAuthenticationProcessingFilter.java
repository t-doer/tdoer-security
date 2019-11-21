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

import com.tdoer.bedrock.Platform;
import com.tdoer.bedrock.service.Service;
import com.tdoer.bedrock.service.ServiceType;
import com.tdoer.security.oauth2.OAuth2Constants;
import com.tdoer.security.oauth2.common.AccessTokenThreadLocalHolder;
import com.tdoer.security.oauth2.common.token.RefreshableTokenTemplate;
import com.tdoer.security.oauth2.common.token.TokenTemplate;
import com.tdoer.security.oauth2.provider.authentication.CloudOAuth2AuthenticationDetails;
import com.tdoer.security.oauth2.provider.authentication.CloudOAuth2AuthenticationDetailsSource;
import com.tdoer.security.oauth2.common.token.ReadingRefreshTokenServices;
import com.tdoer.security.oauth2.util.OAuth2AuthenticationUtil;
import com.tdoer.springboot.util.WebUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.resource.OAuth2AccessDeniedException;
import org.springframework.security.oauth2.common.ExpiringOAuth2RefreshToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.authentication.BearerTokenExtractor;
import org.springframework.security.oauth2.provider.authentication.TokenExtractor;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.HashSet;
import java.util.Map;

/**
 * The filter will intercept all requests and extract access token from request header, and load an
 * authentication object into the SecurityContext. If access token is expired,
 * it will be try to refreshed from Authorization Server for a new one.
 * <br>
 * The filter will intercept all requests, instead only "login" request.
 *
 * @author Htinker Hu (htinker@163.com)
 * @create 2019-11-06
 */
public class AccessTokenAuthenticationProcessingFilter extends GenericFilterBean {

	protected static Logger logger = LoggerFactory.getLogger(AccessTokenAuthenticationProcessingFilter.class);

	protected TokenTemplate tokenTemplate;

	protected ResourceServerTokenServices tokenServices;

	private RequestMatcher loginRequestMatcher = new AntPathRequestMatcher("/login");

	protected CloudOAuth2AuthenticationDetailsSource authenticationDetailsSource =
			new CloudOAuth2AuthenticationDetailsSource();

	protected TokenExtractor tokenExtractor = new BearerTokenExtractor();

	public AccessTokenAuthenticationProcessingFilter(){
	}

	public void setLoginURL(String loginURL){
		if(StringUtils.hasText(loginURL)){
			loginRequestMatcher = new AntPathRequestMatcher(loginURL);
		}
	}
	/**
	 * A token template to be used to obtain an access token.
	 *
	 * @param tokenTemplate a code template, cannot be <code>null</code>
	 */
	public void setTokenTemplate(TokenTemplate tokenTemplate) {
		Assert.notNull(tokenTemplate, "TokenTemplate cannot be null");
		this.tokenTemplate = tokenTemplate;
	}

	/**
	 * Reference to a CheckTokenServices that can validate an OAuth2AccessToken
	 *
	 * @param tokenServices token service, cannot be <code>null</code>
	 */
	public void setTokenServices(ResourceServerTokenServices tokenServices) {
		Assert.notNull(tokenServices, "ResourceServerTokenServices cannot be null");
		this.tokenServices = tokenServices;
	}

	public void setAuthenticationDetailsSource(CloudOAuth2AuthenticationDetailsSource authenticationDetailsSource) {
		Assert.notNull(authenticationDetailsSource, "CloudOAuth2AuthenticationDetailsSource cannot be null");
		this.authenticationDetailsSource = authenticationDetailsSource;
	}

	@Override
	public void afterPropertiesSet() {
		Assert.notNull(tokenTemplate, "AuthorizationCodeTokenTemplate is required");
		Assert.notNull(tokenServices, "ResourceServerTokenServices is required");
	}

	@Override
	public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest)servletRequest;
		HttpServletResponse response = (HttpServletResponse)servletResponse;
		if(!requiresAuthentication(request, response)){
			filterChain.doFilter(request, response);
		}else{
			try{
				Authentication authentication = tokenExtractor.extract(request);
				if(authentication == null){
					String token = (String) authentication.getPrincipal();
					OAuth2AccessToken accessToken = processAccessToken(request, response, token);
					AccessTokenThreadLocalHolder.setAccessToken(accessToken);
					if(!accessToken.getValue().equals(token)){
						logger.info("Token {} is refreshed to {}", token, accessToken.getValue());
						// Access token was refreshed, set the new tokan to response header
						logger.info("Set a new token into response header and cookie: {}", accessToken.getValue());
						WebUtil.addValueIntoResponseHeaderAndCookie(response, request, OAuth2Constants.AUTH_TOKEN, accessToken.getValue());
					}

					authentication = attemptAuthentication(request, response, authentication, accessToken);
					SecurityContextHolder.getContext().setAuthentication(authentication);
				}
			}catch (Exception ex){
				logger.warn("Failed to process access token", ex);
			}finally{
				filterChain.doFilter(servletRequest, servletResponse);
			}
		}
	}

	protected boolean requiresAuthentication(HttpServletRequest request, HttpServletResponse response) {
		return (loginRequestMatcher == null || !loginRequestMatcher.matches(request));
	}

	protected OAuth2AccessToken processAccessToken(HttpServletRequest request, HttpServletResponse response,
									  String token){
		OAuth2AccessToken accessToken = tokenServices.readAccessToken(token);
		logger.debug("Read OAuth2AccessToken from token services for the token: {} -> {}", token, accessToken);
		Service service = Platform.getCurrentService();
		ServiceType serviceType = service.getType();
		if(serviceType != ServiceType.GATEWAY && serviceType != ServiceType.AUTHORIZATION){
			logger.debug("Current service ({}) is neither gateway nor authorization service, return stored access " +
							"token directly: {}", service.getCode(), accessToken);
			return accessToken;
		}

		OAuth2RefreshToken refreshToken = null;

		if(accessToken == null){
			// Maybe access token is expired and removed by Redis, read refresh token for the token value
			if(tokenServices instanceof ReadingRefreshTokenServices){
				logger.debug("Trying to reading OAuth2RefreshToken from token services");
				refreshToken = ((ReadingRefreshTokenServices) tokenServices).readRefreshTokenForToken(token);
				logger.debug("Read OAuth2RefreshToken from token services for the token: {} -> {}", token, refreshToken);

				if(refreshToken == null){
					// Access token was revoked
					logger.info("Neither OAuth2AccessToken nor OAuth2RefreshToken is found for the access token: {}",
							token);
				}else{
					logger.debug("Trying to refresh the token from stored refresh token: {} - {}", token, refreshToken);
					OAuth2AccessToken newToken = refreshToken(request, token, refreshToken);
					if(newToken != null){
						logger.info("Token was refreshed successfully: {} -> {}", token, newToken);
						accessToken = newToken;
					}else{
						logger.info("Failed to refresh token for the token: {}", token);
					}
				}
			}

		}else{
			// Maybe the access token has been replaced when kicked off
			Map<String, Object> map = accessToken.getAdditionalInformation();
			if(map != null){
				Object kickedOffByToken = map.get(OAuth2Constants.KICKED_OFF_BY);
				logger.debug("Read replacement grant details for the token: {} -> {}", accessToken, kickedOffByToken);
				if(kickedOffByToken != null){
					Date kickedOffOnDate = (Date) map.get(OAuth2Constants.KICKED_OFF_ON);
					logger.info("The token '{}' is replaced by the token '{}' on {}", token, kickedOffByToken,
							kickedOffOnDate);
					throw new InvalidTokenException("Invalid token (" + token + "), it's kicked off by token (" + kickedOffByToken + ") on " + kickedOffOnDate);
				}
			}

			if(accessToken.isExpired()){
				refreshToken = accessToken.getRefreshToken();
				logger.info("Expired access token and its OAuth2RefreshToken: {} -> {}", accessToken, refreshToken);

				if(refreshToken != null){
					if(tokenTemplate instanceof RefreshableTokenTemplate){
						logger.debug("Trying to refresh the expired access token: {} with refresh token: {}", accessToken, refreshToken);
						OAuth2AccessToken newToken = null;
						try{
							newToken = refreshToken(request, token, refreshToken);
						}catch(Exception ex){
							logger.error("Failed to refresh the token (" + accessToken + ") with refresh token (" + refreshToken + ")",
									ex);
						}
						if(newToken != null){
							logger.info("Token was refreshed successfully: {} -> {}", accessToken, newToken);
							accessToken = newToken;
						}
					}else{
						logger.debug("Token template dose not support refreshing expired access token: {}", accessToken);
					}
				}else{
					logger.info("Token '{}' is expired without refresh token", accessToken);
					// Expired token and no way to refresh
					throw new InvalidTokenException("Expired token: " + accessToken);
				}
			}
		}

		if(accessToken == null){
			throw new InvalidTokenException("Invalid token: " + token);
		}
		return accessToken;
	}

	protected OAuth2AccessToken refreshToken(HttpServletRequest request, String requestToken,
											 OAuth2RefreshToken refreshToken) {
		if (refreshToken instanceof ExpiringOAuth2RefreshToken) {
			ExpiringOAuth2RefreshToken expiring = (ExpiringOAuth2RefreshToken) refreshToken;
			if (System.currentTimeMillis() > expiring.getExpiration().getTime()) {
				logger.debug("Both token '{}' and refresh token '{}' are expired", requestToken, refreshToken.getValue());
				// Refresh token is expired
				throw new InvalidTokenException("Both token and refresh token are expired: " + requestToken + "," + refreshToken.getValue());
			}
		}

		return ((RefreshableTokenTemplate)tokenTemplate).refreshAccessToken(request, refreshToken);
	}

	protected void checkClientDetails(OAuth2Authentication auth, OAuth2AccessToken token) {
		String storedClientId = OAuth2AuthenticationUtil.getClientId(auth);
		String currentClientId = Platform.getCurrentEnvironment().getTenantClient().getGuid();
		if (!currentClientId.equals(storedClientId)) {
			logger.warn("Request tenantId client's GUID '{}' dose not match the token's client id '{}'",
					currentClientId, storedClientId);
			throw new InvalidTokenException("Request tenantId client's GUID '" + currentClientId + "' dose not match " +
					"token's client id '" + storedClientId + "' of the token: " + token);
		}

		String[] allowed = Platform.getCurrentEnvironment().getClient().getScopes();
		HashSet<String> set = new HashSet<>(allowed.length);
		for(String scp : allowed){
			set.add(scp);
		}

		for (String scope : auth.getOAuth2Request().getScope()) {
			if (!set.contains(scope)) {
				throw new OAuth2AccessDeniedException(
						"Invalid token contains disallowed scope (" + scope + ") in this client's scopes: " + allowed);
			}
		}
	}

	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response,
												Authentication authentication, OAuth2AccessToken accessToken)
			throws AuthenticationException, IOException, ServletException {

		logger.debug("Loading OAuth2Authentication from token service for the token '{}'", accessToken);
		OAuth2Authentication auth = tokenServices.loadAuthentication(accessToken.getValue());
		logger.debug("Loaded OAuth2Authentication '{}' for the token '{}'", auth, accessToken);
		if (auth == null) {
			// Maybe user is removed or its status is not valid any more
			logger.info("Loaded OAuth2Authentication is null for the token '{}'", accessToken);
			throw new InvalidTokenException("No user authentication for the token: " + accessToken);
		}

		CloudOAuth2AuthenticationDetails details = authenticationDetailsSource.buildDetails(request);
		String storedUserAgent = OAuth2AuthenticationUtil.getUserAgent(auth);
		if(!details.getUserAgent().equals(storedUserAgent)){
			logger.info("Invalid token ({}), request user agent ({}) dose not match stored authentication user agent " +
					"({})", accessToken, details.getUserAgent(), storedUserAgent);
			throw new InvalidTokenException("User agent was changed of the token: " + accessToken);
		}

		checkClientDetails(auth, accessToken);

		auth.setDetails(authentication.getDetails());
		auth.setAuthenticated(true);

		return auth;
	}
}