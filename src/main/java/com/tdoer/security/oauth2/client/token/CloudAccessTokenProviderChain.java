/*
 * Copyright 2002-2011 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.tdoer.security.oauth2.client.token;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.resource.OAuth2AccessDeniedException;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.resource.UserRedirectRequiredException;
import org.springframework.security.oauth2.client.token.AccessTokenProvider;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.client.token.ClientTokenServices;
import org.springframework.security.oauth2.client.token.OAuth2AccessTokenSupport;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;

import java.util.Collections;
import java.util.List;

/**
 * Copy and customized form {@link org.springframework.security.oauth2.client.token.AccessTokenProviderChain}.
 * In T-doer SaaS framework, user is authenticated by Token Server, not in Client, so to retrive a token dose
 * not require that user is authenticated.
 *
 * - Htinker Hu, 2019/07/13
 */
public class CloudAccessTokenProviderChain extends OAuth2AccessTokenSupport
		implements AccessTokenProvider {

	private final List<AccessTokenProvider> chain;

	private ClientTokenServices clientTokenServices;

	public CloudAccessTokenProviderChain(List<? extends AccessTokenProvider> chain) {
		this.chain = chain == null ? Collections.<AccessTokenProvider> emptyList()
				: Collections.unmodifiableList(chain);
	}

	/**
	 * Token services for long-term persistence of access tokens.
	 *
	 * @param clientTokenServices the clientTokenServices to set
	 */
	public void setClientTokenServices(ClientTokenServices clientTokenServices) {
		this.clientTokenServices = clientTokenServices;
	}

	public boolean supportsResource(OAuth2ProtectedResourceDetails resource) {
		for (AccessTokenProvider tokenProvider : chain) {
			if (tokenProvider.supportsResource(resource)) {
				return true;
			}
		}
		return false;
	}

	public boolean supportsRefresh(OAuth2ProtectedResourceDetails resource) {
		for (AccessTokenProvider tokenProvider : chain) {
			if (tokenProvider.supportsRefresh(resource)) {
				return true;
			}
		}
		return false;
	}

	public OAuth2AccessToken obtainAccessToken(OAuth2ProtectedResourceDetails resource,
			AccessTokenRequest request)
			throws UserRedirectRequiredException, AccessDeniedException {

		// Customization, dose not require that user is authenticated
        // - Htinker Hu, 2019/07/13

		OAuth2AccessToken accessToken = null;
		OAuth2AccessToken existingToken = null;
		Authentication auth = SecurityContextHolder.getContext().getAuthentication();

		if (resource.isClientOnly()) {
			existingToken = request.getExistingToken();
			if (existingToken == null && clientTokenServices != null) {
				existingToken = clientTokenServices.getAccessToken(resource, auth);
			}

			if (existingToken != null) {
				if (existingToken.isExpired()) {
					if (clientTokenServices != null) {
						clientTokenServices.removeAccessToken(resource, auth);
					}
					OAuth2RefreshToken refreshToken = existingToken.getRefreshToken();
					if (refreshToken != null && !resource.isClientOnly()) {
						accessToken = refreshAccessToken(resource, refreshToken, request);
					}
				}
				else {
					accessToken = existingToken;
				}
			}
		}
		// Give unauthenticated users a chance to get a token and be redirected

		if (accessToken == null) {
			// looks like we need to try to obtain a new token.
			accessToken = obtainNewAccessTokenInternal(resource, request);

			if (accessToken == null) {
				throw new IllegalStateException(
						"An OAuth 2 access token must be obtained or an exception thrown.");
			}
		}

		if (clientTokenServices != null
				&& (resource.isClientOnly())) {
			clientTokenServices.saveAccessToken(resource, auth, accessToken);
		}

		return accessToken;
	}

	protected OAuth2AccessToken obtainNewAccessTokenInternal(
			OAuth2ProtectedResourceDetails details, AccessTokenRequest request)
			throws UserRedirectRequiredException, AccessDeniedException {

		if (request.isError()) {
			// there was an oauth error...
			throw OAuth2Exception.valueOf(request.toSingleValueMap());
		}

		for (AccessTokenProvider tokenProvider : chain) {
			if (tokenProvider.supportsResource(details)) {
				return tokenProvider.obtainAccessToken(details, request);
			}
		}

		throw new OAuth2AccessDeniedException(
				"Unable to obtain a new access token for resource '" + details.getId()
						+ "'. The provider manager is not configured to support it.",
				details);
	}

	/**
	 * Obtain a new access token for the specified resource using the refresh token.
	 *
	 * @param resource The resource.
	 * @param refreshToken The refresh token.
	 * @return The access token, or null if failed.
	 * @throws UserRedirectRequiredException
	 */
	public OAuth2AccessToken refreshAccessToken(OAuth2ProtectedResourceDetails resource,
			OAuth2RefreshToken refreshToken, AccessTokenRequest request)
			throws UserRedirectRequiredException {
		for (AccessTokenProvider tokenProvider : chain) {
			if (tokenProvider.supportsRefresh(resource)) {
				DefaultOAuth2AccessToken refreshedAccessToken = new DefaultOAuth2AccessToken(
						tokenProvider.refreshAccessToken(resource, refreshToken,
								request));
				if (refreshedAccessToken.getRefreshToken() == null) {
					// Fixes gh-712
					refreshedAccessToken.setRefreshToken(refreshToken);
				}
				return refreshedAccessToken;
			}
		}
		throw new OAuth2AccessDeniedException(
				"Unable to obtain a new access token for resource '" + resource.getId()
						+ "'. The provider manager is not configured to support it.",
				resource);
	}

}
