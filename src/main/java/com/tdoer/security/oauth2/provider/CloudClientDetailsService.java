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
package com.tdoer.security.oauth2.provider;

import com.tdoer.bedrock.Platform;
import com.tdoer.bedrock.tenant.TenantClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.ClientRegistrationException;
import org.springframework.util.Assert;
/**
 * @author Htinker Hu (htinker@163.com)
 * @create 2017-09-19
 */
public class CloudClientDetailsService implements ClientDetailsService {
    private static Logger logger = LoggerFactory.getLogger(CloudClientDetailsService.class);
    /**
     * Load a tenant client by the client id, that's, GUID. This method must not
     * return null.
     *
     * @param clientId The client id.
     * @return The client details (never null).
     * @throws ClientRegistrationException If the client account is locked, expired, disabled, or invalid for any other reason.
     */
    @Override
    public ClientDetails loadClientByClientId(String clientId) throws ClientRegistrationException {

        TenantClient client = Platform.getCurrentEnvironment().getTenantClient();

        logger.info("Current tenant client's GUID and request client Id are: {} - {}", client.getGuid(), clientId);
        Assert.isTrue(client.getGuid().equals(clientId), "Tenant client's GUID dose not matched, there must be " +
                "some request goes wrong");

        return new CloudClientDetails(client);
    }
}
