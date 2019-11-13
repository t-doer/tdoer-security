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
package com.tdoer.security.oauth2.provider.endpoint;

import com.tdoer.security.oauth2.provider.CloudClientDetails;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.endpoint.DefaultRedirectResolver;
/**
 * @author Htinker Hu (htinker@163.com)
 * @create 2017-09-19
 */
public class TrustRedirectResolver extends DefaultRedirectResolver {
    @Override
    public String resolveRedirect(String requestedRedirect, ClientDetails clientDetails) throws OAuth2Exception {
        if(clientDetails instanceof CloudClientDetails){
            CloudClientDetails cl = (CloudClientDetails)clientDetails;
            if(cl.getTenantClient().getClient().isTrusted()){
                return requestedRedirect;
            }
        }

        return super.resolveRedirect(requestedRedirect, clientDetails);
    }
}
