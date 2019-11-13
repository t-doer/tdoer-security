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
package com.tdoer.security.autoconfigure;

import com.tdoer.bedrock.web.CloudEnvironmentProcessingFilter;
import com.tdoer.bedrock.web.CloudServiceCheckAccessFilter;
import com.tdoer.security.oauth2.client.CloudOAuth2ClientProperties;
import com.tdoer.security.oauth2.client.filter.AccessTokenAuthenticationProcessingFilter;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter;
import org.springframework.util.Assert;

/**
 * @author Htinker Hu (htinker@163.com)
 * @create 2019-11-11
 */
public class CloudServiceConfigurer {
    private ApplicationContext applicationContext;
    private CloudOAuth2ClientProperties clientProperties;

    public CloudServiceConfigurer(ApplicationContext applicationContext, CloudOAuth2ClientProperties clientProperties) {
        Assert.notNull(applicationContext, "ApplicationContext cannot be null");
        Assert.notNull(clientProperties, "CloudOAuth2ClientProperties cannot be null");
        this.applicationContext = applicationContext;
        this.clientProperties = clientProperties;
    }

    public void configure(HttpSecurity http) throws Exception {
        // Delay the processing of the filter until we know the
        // SessionAuthenticationStrategy is available:
        // TODO ADD FILTERS HERE
        http.addFilterBefore(cloudEnvironmentProcessingFilter(), WebAsyncManagerIntegrationFilter.class);
        http.addFilterBefore(cloudServiceCheckAccessFilter(), SecurityContextPersistenceFilter.class);
        http.addFilterAfter(accessTokenAuthenticationProcessingFilter(), SecurityContextPersistenceFilter.class);
    }

    protected CloudEnvironmentProcessingFilter cloudEnvironmentProcessingFilter(){
        CloudEnvironmentProcessingFilter filter = new CloudEnvironmentProcessingFilter();
        return filter;
    }

    protected CloudServiceCheckAccessFilter cloudServiceCheckAccessFilter(){
        CloudServiceCheckAccessFilter filter = new CloudServiceCheckAccessFilter();
        return filter;
    }

    protected AccessTokenAuthenticationProcessingFilter accessTokenAuthenticationProcessingFilter(){
        AccessTokenAuthenticationProcessingFilter filter = new AccessTokenAuthenticationProcessingFilter();
        return filter;
    }
}
