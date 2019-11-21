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
package com.tdoer.security.oauth2.client.token;

import com.tdoer.security.oauth2.common.AccessTokenThreadLocalHolder;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.client.token.DefaultAccessTokenRequest;
import org.springframework.security.oauth2.common.OAuth2AccessToken;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

/**
 * The OAuth 2 security context (for a specific user or client or combination thereof).
 * It's a request-based instance.
 * 
 * @author Dave Syer
 */
public class CloudOAuth2ClientContext implements OAuth2ClientContext, Serializable {

	private static final long serialVersionUID = 914967629530462926L;

	private AccessTokenRequest accessTokenRequest;

	private Map<String, Object> state = new HashMap<String, Object>();

	public CloudOAuth2ClientContext() {
		this(new DefaultAccessTokenRequest());
	}

	public CloudOAuth2ClientContext(AccessTokenRequest accessTokenRequest) {
		this.accessTokenRequest = accessTokenRequest;
	}

	public CloudOAuth2ClientContext(OAuth2AccessToken accessToken) {
		AccessTokenThreadLocalHolder.setAccessToken(accessToken);
		this.accessTokenRequest = new DefaultAccessTokenRequest();
	}

	public OAuth2AccessToken getAccessToken() {
		return AccessTokenThreadLocalHolder.getAccessToken();
	}

	public void setAccessToken(OAuth2AccessToken accessToken) {
		AccessTokenThreadLocalHolder.setAccessToken(accessToken);
		this.accessTokenRequest.setExistingToken(accessToken);
	}

	public AccessTokenRequest getAccessTokenRequest() {
		return accessTokenRequest;
	}

	public void setPreservedState(String stateKey, Object preservedState) {
		// todo, need to utilize redis and cookie to keep state
	    state.put(stateKey, preservedState);
	}

	public Object removePreservedState(String stateKey) {
		return state.remove(stateKey);
	}

}
