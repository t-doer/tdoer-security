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
package com.tdoer.security.oauth2.client.token.grant.password;

import com.tdoer.security.oauth2.http.converter.DelegatingFormOAuth2ExceptionHttpMessageConverter;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordAccessTokenProvider;
import org.springframework.web.client.RestTemplate;

import java.util.ArrayList;
/**
 * @author Htinker Hu (htinker@163.com)
 * @create 2017-09-19
 */
public class CloudUserPasswordTokenProvider extends ResourceOwnerPasswordAccessTokenProvider {

	public CloudUserPasswordTokenProvider(RestTemplate restTemplate){

		ArrayList<HttpMessageConverter<?>> messageConverters = new ArrayList<>(restTemplate.getMessageConverters());
		// Add customized converter to read more OAuth2Exception
		messageConverters.add(new DelegatingFormOAuth2ExceptionHttpMessageConverter());

		setMessageConverters(messageConverters);
		setInterceptors(restTemplate.getInterceptors());
		setRequestFactory(restTemplate.getRequestFactory());
	}
}
