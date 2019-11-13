/*
 * Copyright 2012-2017 the original author or authors.
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

package com.tdoer.security.oauth2.config.annotation.web.configuration;

import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;

import java.util.ArrayList;
import java.util.List;

/**
 * Configuration properties for OAuth2 Resources, holds "security.oauth2.resource.*" settings.
 */
public class ResourceServerProperties {

    private static final String ALL = "/**";

	/**
	 * Identifier of the resource.
	 */
	private String id;

	/**
	 * URI of the user endpoint.
	 */
	private String userInfoUri;

	/**
	 * The token type to send when using the userInfoUri.
	 */
	private String tokenType = DefaultOAuth2AccessToken.BEARER_TYPE;

    private List<String> protectedResources;

	public ResourceServerProperties() {
        protectedResources = new ArrayList<>();
        protectedResources.add(ALL);
	}

	public String getId() {
		return this.id;
	}

	public void setId(String id) {
		this.id = id;
	}

	public String getUserInfoUri() {
		return this.userInfoUri;
	}

	public void setUserInfoUri(String userInfoUri) {
		this.userInfoUri = userInfoUri;
	}

	public String getTokenType() {
		return this.tokenType;
	}

	public void setTokenType(String tokenType) {
		this.tokenType = tokenType;
	}

    public void setProtectedResources(List<String> protectedResources) {
        this.protectedResources = protectedResources;
    }

    public List<String> getProtectedResources() {
        return protectedResources;
    }
}
