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
package com.tdoer.security.oauth2.client;

import com.tdoer.bedrock.CloudEnvironment;
import com.tdoer.bedrock.Platform;
import org.springframework.security.oauth2.client.resource.BaseOAuth2ProtectedResourceDetails;

import java.util.ArrayList;
import java.util.List;

/**
 * Configuration properties for OAuth2 Client, holds "security.oauth2.client.*" settings.
 *
 * @author Htinker Hu (htinker@163.com)
 * @create 2017-09-19
 */
public class CloudOAuth2ClientProperties extends BaseOAuth2ProtectedResourceDetails {
    public static final String DEFAULT_LOGIN_PATH = "/login";

    public static final String DEFAULT_LOGOUT_PATH = "/logout";

    // ImplicitResourceDetails or AuthorizationCodeResourceDetails specifically
    private String preEstablishedRedirectUri;

    private String userAuthorizationUri;

    private boolean useCurrentUri = true;

    // Extensions
    private String revokeTokenUri;

    private String authorizationServerLogoutUri;

    private String targetUrlParameter = "redirect_url";

    private String authLogoutParameter = "authLogoutUrl";
    /**
     * Path to the login page, i.e. the one that triggers the redirect to the OAuth2
     * Authorization Server.
     */
    private String loginPath = DEFAULT_LOGIN_PATH;

    private String logoutPath = DEFAULT_LOGOUT_PATH;

    @Override
    public String getId() {
        return Platform.getCurrentService().getCode();
    }

    @Override
    public String getClientId() {
        CloudEnvironment env = Platform.getCurrentEnvironment();
        return env.getTenantClient().getGuid();
    }

    @Override
    public String getClientSecret() {
        CloudEnvironment env = Platform.getCurrentEnvironment();
        return env.getTenantClient().getSecret();
    }

    @Override
    public List<String> getScope() {

        String[] scopes = Platform.getCurrentEnvironment().getClient().getScopes();
        ArrayList<String> list = new ArrayList<>(scopes.length);
        for(String scope : scopes){
            list.add(scope);
        }
        return list;
    }

    @Override
    public boolean isScoped() {
        List<String> scope = getScope();
        return (scope != null && !scope.isEmpty());
    }

    public String getLoginPath() {
        return this.loginPath;
    }

    public void setLoginPath(String loginPath) {
        this.loginPath = loginPath;
    }

    public String getLogoutPath() {
        return logoutPath;
    }

    public void setLogoutPath(String logoutPath) {
        this.logoutPath = logoutPath;
    }

    public String getAuthLogoutParameter() {
        return authLogoutParameter;
    }

    public void setAuthLogoutParameter(String authLogoutParameter) {
        this.authLogoutParameter = authLogoutParameter;
    }

    /**
     * Flag to signal that the current URI (if set) in the request should be used in preference to the pre-established
     * redirect URI.
     *
     * @param useCurrentUri the flag value to set (default true)
     */
    public void setUseCurrentUri(boolean useCurrentUri) {
        this.useCurrentUri = useCurrentUri;
    }

    /**
     * Flag to signal that the current URI (if set) in the request should be used in preference to the pre-established
     * redirect URI.
     *
     * @return the flag value
     */
    public boolean isUseCurrentUri() {
        return useCurrentUri;
    }

    /**
     * The URI to which the user is to be redirected to authorize an access token.
     *
     * @return The URI to which the user is to be redirected to authorize an access token.
     */
    public String getUserAuthorizationUri() {
        return userAuthorizationUri;
    }

    /**
     * The URI to which the user is to be redirected to authorize an access token.
     *
     * @param userAuthorizationUri The URI to which the user is to be redirected to authorize an access token.
     */
    public void setUserAuthorizationUri(String userAuthorizationUri) {
        this.userAuthorizationUri = userAuthorizationUri;
    }

    /**
     * The redirect URI that has been pre-established with the server. If present, the redirect URI will be omitted from
     * the user authorization request because the server doesn't need to know it.
     *
     * @return The redirect URI that has been pre-established with the server.
     */
    public String getPreEstablishedRedirectUri() {
        return preEstablishedRedirectUri;
    }

    /**
     * The redirect URI that has been pre-established with the server. If present, the redirect URI will be omitted from
     * the user authorization request because the server doesn't need to know it.
     *
     * @param preEstablishedRedirectUri The redirect URI that has been pre-established with the server.
     */
    public void setPreEstablishedRedirectUri(String preEstablishedRedirectUri) {
        this.preEstablishedRedirectUri = preEstablishedRedirectUri;
    }

    public String getRevokeTokenUri() {
        return revokeTokenUri;
    }

    public void setRevokeTokenUri(String revokeTokenUri) {
        this.revokeTokenUri = revokeTokenUri;
    }

    public String getAuthorizationServerLogoutUri() {
        return authorizationServerLogoutUri;
    }

    public void setAuthorizationServerLogoutUri(String authorizationServerLogoutUri) {
        this.authorizationServerLogoutUri = authorizationServerLogoutUri;
    }

    public String getTargetUrlParameter() {
        return targetUrlParameter;
    }

    public void setTargetUrlParameter(String targetUrlParameter) {
        this.targetUrlParameter = targetUrlParameter;
    }
}
