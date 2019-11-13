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

import org.springframework.security.oauth2.client.resource.BaseOAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsResourceDetails;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.client.token.grant.implicit.ImplicitResourceDetails;
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordResourceDetails;

/**
 * Client's Identifier and credentials do not read from static configurations, instead,
 * from CloudEnvironment's TenantClient object, and Auth2ProtectedResourceDetails's `clientId` is
 * CloudEnvironment's TenantClient's GUID.
 *
 * @author Htinker Hu (htinker@163.com)
 * @create 2017-09-19
 */
public class CloudResourceDetailsFactory {

    private CloudResourceDetailsFactory(){}

    protected static void setBaseDetails(CloudOAuth2ClientProperties clientProperties, BaseOAuth2ProtectedResourceDetails baseDetails){
        baseDetails.setTokenName(clientProperties.getTokenName());
        baseDetails.setAccessTokenUri(clientProperties.getAccessTokenUri());
        baseDetails.setAuthenticationScheme(clientProperties.getAuthenticationScheme());
        baseDetails.setClientAuthenticationScheme(clientProperties.getClientAuthenticationScheme());
    }

    public static AuthorizationCodeResourceDetails newAuthorizationCodeResourceDetails(CloudOAuth2ClientProperties clientProperties){
        AuthorizationCodeResourceDetails newDetails = new AuthorizationCodeResourceDetails();

        setBaseDetails(clientProperties, newDetails);

        newDetails.setPreEstablishedRedirectUri(clientProperties.getPreEstablishedRedirectUri());
        newDetails.setUseCurrentUri(clientProperties.isUseCurrentUri());
        newDetails.setUserAuthorizationUri(clientProperties.getUserAuthorizationUri());
        return newDetails;
    }

    public static ImplicitResourceDetails newImplicitResourceDetails(CloudOAuth2ClientProperties clientProperties){
        ImplicitResourceDetails newDetails = new ImplicitResourceDetails();

        setBaseDetails(clientProperties, newDetails);


        newDetails.setPreEstablishedRedirectUri(clientProperties.getPreEstablishedRedirectUri());
        newDetails.setUseCurrentUri(clientProperties.isUseCurrentUri());
        newDetails.setUserAuthorizationUri(clientProperties.getUserAuthorizationUri());
        return newDetails;
    }

    public static ResourceOwnerPasswordResourceDetails newResourceOwnerPasswordResourceDetails(CloudOAuth2ClientProperties clientProperties, String account, String password){
        ResourceOwnerPasswordResourceDetails newDetails = new ResourceOwnerPasswordResourceDetails();

        setBaseDetails(clientProperties, newDetails);

        newDetails.setUsername(account);
        newDetails.setPassword(password);

        return newDetails;
    }

    public static ClientCredentialsResourceDetails newClientCredentialsResourceDetails(CloudOAuth2ClientProperties clientProperties){
        ClientCredentialsResourceDetails newDetails = new ClientCredentialsResourceDetails();

        setBaseDetails(clientProperties, newDetails);

        return newDetails;
    }

}
