/*
 * Copyright 2017-2019 T-Doer (tdoer.com).
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
package com.tdoer.security.oauth2.client;

import com.tdoer.bedrock.CloudEnvironment;
import com.tdoer.bedrock.Platform;
import com.tdoer.bedrock.PlatformConstants;
import org.springframework.http.client.ClientHttpRequest;
import org.springframework.security.oauth2.client.DefaultOAuth2RequestAuthenticator;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;

/**
 * @author Htinker Hu (htinker@163.com)
 * @create 2017-09-19
 */
public class CloudOAuth2RequestAuthenticator extends DefaultOAuth2RequestAuthenticator {
    /**
     * Add access token info into request header, to the simple form "TOKEN_TYPE TOKEN_VALUE",
     * and add Cloud Environment Digest into request header.
     *
     * @param resource
     * @param clientContext
     * @param request
     */
	@Override
	public void authenticate(OAuth2ProtectedResourceDetails resource, OAuth2ClientContext clientContext, ClientHttpRequest request) {
		super.authenticate(resource, clientContext, request);

		// 1. Transfer cloud environment digest which CloudEnvironmentParseFilter will parse it
        CloudEnvironment env = Platform.getCurrentEnvironment();
        request.getHeaders().set(PlatformConstants.ENVIRONMENT_DIGEST, env.getDigest().toDigestString());

        // 2. Transfer user information, token process filter will parse out it
        // todo implement it
	}

}
