/*
 * Copyright 2006-2011 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */


package com.tdoer.security.oauth2.provider.authentication;

import org.springframework.security.authentication.AuthenticationDetailsSource;

import javax.servlet.http.HttpServletRequest;

/**
 * Copy from and modify {@link org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetailsSource},
 * by returning a customized {@link CloudOAuth2AuthenticationDetails}.
 * The class should be configured into Auth Server's
 * form login.
 *
 * <pre>
 *     protected void configure(HttpSecurity http) throws Exception {
 *         http
 *                 .formLogin().authenticationDetailsSource(new WebAuthenticationDetailsSource())
 *                 // ...
 *     }
 * </pre>
 *
 *
 * -- Likai Hu, 2018/0/13.
 *
 * A source for authentication details in an OAuth2 protected Resource.
 * 
 * @author Dave Syer
 * 
 */
public class CloudOAuth2AuthenticationDetailsSource implements
        AuthenticationDetailsSource<HttpServletRequest, CloudOAuth2AuthenticationDetails> {

	public CloudOAuth2AuthenticationDetails buildDetails(HttpServletRequest context) {
		return new CloudOAuth2AuthenticationDetails(context);
	}

}
