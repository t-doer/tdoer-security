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

import com.tdoer.bedrock.product.Client;
import com.tdoer.bedrock.product.ClientRole;
import com.tdoer.bedrock.product.ClientServiceInstallation;
import com.tdoer.bedrock.tenant.TenantClient;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.util.Assert;

import java.util.*;
/**
 * @author Htinker Hu (htinker@163.com)
 * @create 2017-09-19
 */
public class CloudClientDetails implements ClientDetails {
    private TenantClient tenantClient;

    public CloudClientDetails(TenantClient tenantClient) {
        Assert.notNull(tenantClient, "TenantClient cannot be null");
        this.tenantClient = tenantClient;
    }

    public TenantClient getTenantClient() {
        return tenantClient;
    }

    /**
     * The client id.
     *
     * @return The client id.
     */
    @Override
    public String getClientId() {
        return tenantClient.getGuid();
    }

    /**
     * The Ids of resource server  that this client can access. Can be ignored by callers if empty.
     *
     * @return The resources of this client.
     */
    @Override
    public Set<String> getResourceIds() {
        ArrayList<ClientServiceInstallation> list = new ArrayList<>();
        tenantClient.getClient().getClientConfig().listAccessibleService(list);

        HashSet<String> set = new HashSet<>(list.size());
        for(ClientServiceInstallation service : list){
            set.add(service.getService().getCode());
        }
        return set;
    }

    /**
     * Whether a secret is required to authenticate this client.
     *
     * @return Whether a secret is required to authenticate this client.
     */
    @Override
    public boolean isSecretRequired() {
        return (tenantClient.getSecret() != null);
    }

    /**
     * The client secret. Ignored if the {@link #isSecretRequired() secret isn't required}.
     *
     * @return The client secret.
     */
    @Override
    public String getClientSecret() {
        return tenantClient.getSecret();
    }

    /**
     * Whether this client is limited to a specific scope. If false, the scope of the authentication request will be
     * ignored.
     *
     * @return Whether this client is limited to a specific scope.
     */
    @Override
    public boolean isScoped() {
        Client client = tenantClient.getClient();
        return (client.getScopes() != null && client.getScopes().length != 0);
    }

    /**
     * The scope of this client. Empty if the client isn't scoped.
     *
     * @return The scope of this client.
     */
    @Override
    public Set<String> getScope() {
        if(isScoped()){
            String[] scopes = tenantClient.getClient().getScopes();
            HashSet<String> set = new HashSet<>(scopes.length);
            for(String scope : scopes){
                set.add(scope);
            }
            return set;
        }

        return null;
    }

    /**
     * The grant types for which this client is authorized.
     *
     * @return The grant types for which this client is authorized.
     */
    @Override
    public Set<String> getAuthorizedGrantTypes() {
        String[] grantTypes = tenantClient.getClient().getClientConfig().getTokenConfig().getGrantTypes();
        if(grantTypes != null){
            HashSet<String> set = new HashSet<>(grantTypes.length);
            for(String grantType : grantTypes){
                set.add(grantType);
            }
            return set;
        }
        return null;
    }

    /**
     * The pre-defined redirect URI for this client to use during the "authorization_code" access grant. See OAuth spec,
     * section 4.1.1.
     *
     * @return The pre-defined redirect URI for this client.
     */
    @Override
    public Set<String> getRegisteredRedirectUri() {
        String uri = tenantClient.getClient().getClientConfig().getTokenConfig().getWebRedirectURI();
        if(uri != null){
            HashSet<String> set = new HashSet<>(1);
            set.add(uri);
            return set;
        }
        return null;
    }

    /**
     * Returns the authorities that are granted to the OAuth client. Cannot return <code>null</code>.
     * Note that these are NOT the authorities that are granted to the user with an authorized access token.
     * Instead, these authorities are inherent to the client itself.
     *
     * @return the authorities (never <code>null</code>)
     */
    @Override
    public Collection<GrantedAuthority> getAuthorities() {
        ClientRole[] roles = tenantClient.getClient().getRoles();
        if(roles != null){
            ArrayList<GrantedAuthority> list = new ArrayList<>(roles.length);
            for(ClientRole role : roles){
                list.add(role);
            }
            return list;
        }
        return null;
    }

    /**
     * The access token validity period for this client. Null if not set explicitly (implementations might use that fact
     * to provide a default value for instance).
     *
     * @return the access token validity period
     */
    @Override
    public Integer getAccessTokenValiditySeconds() {
        return tenantClient.getClient().getClientConfig().getTokenConfig().getAccessTokenValidityInSeconds();
    }

    /**
     * The refresh token validity period for this client. Null for default value set by token service, and
     * zero or negative for non-expiring tokens.
     *
     * @return the refresh token validity period
     */
    @Override
    public Integer getRefreshTokenValiditySeconds() {
        return tenantClient.getClient().getClientConfig().getTokenConfig().getRefreshTokenValidityInSeconds();
    }

    /**
     * Test whether client needs user approval for a particular scope.
     *
     * @param scope the scope to consider
     * @return true if this client does not need user approval
     */
    @Override
    public boolean isAutoApprove(String scope) {
        String[] approvals = tenantClient.getClient().getClientConfig().getTokenConfig().getAutoApprovals();
        if (approvals == null) {
            return false;
        }
        for (String auto : approvals) {
            if (auto.equals("true") || scope.matches(auto)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Additional information for this client, not needed by the vanilla OAuth protocol but might be useful, for example,
     * for storing descriptive information.
     *
     * @return a map of additional information
     */
    @Override
    public Map<String, Object> getAdditionalInformation() {
        return null;
    }
}
