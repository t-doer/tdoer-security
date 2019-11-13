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

import com.tdoer.security.oauth2.client.token.CloudOAuth2ClientContext;
import org.springframework.http.HttpMethod;
import org.springframework.http.client.ClientHttpRequest;
import org.springframework.security.oauth2.client.OAuth2RequestAuthenticator;
import org.springframework.security.oauth2.client.http.AccessTokenRequiredException;
import org.springframework.security.oauth2.client.http.OAuth2ErrorHandler;
import org.springframework.security.oauth2.client.resource.OAuth2AccessDeniedException;
import org.springframework.security.oauth2.common.AuthenticationScheme;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.util.Assert;
import org.springframework.web.client.*;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;

/**
 * Rest template that is able to make OAuth2-authenticated REST requests with the credentials of the provided resource.
 * Since it's a rest template, it can also be used for common rest requests to web servers.
 *
 * To make a call to ResourceSever, access token is needed.
 *
 * @author Htinker Hu
 */
public class CloudResourceRestTemplate extends RestTemplate {

    private final CloudOAuth2ClientProperties clientProperties;

    private OAuth2RequestAuthenticator authenticator = new CloudOAuth2RequestAuthenticator();

    private CloudOAuth2ClientContext clientContext;

    public CloudResourceRestTemplate(CloudOAuth2ClientProperties clientProperties, CloudOAuth2ClientContext clientContext) {
        Assert.notNull(clientProperties, "Client properties cannot be null");
        Assert.notNull(clientContext, "OAuth2ClientContext cannot be null");

        this.clientProperties = clientProperties;
        this.clientContext = clientContext;
        setErrorHandler(new OAuth2ErrorHandler(clientProperties));
    }

    public CloudOAuth2ClientProperties getClientProperties() {
        return clientProperties;
    }

    public void setAuthenticator(OAuth2RequestAuthenticator authenticator) {
        this.authenticator = authenticator;
    }

    @Override
    public void setErrorHandler(ResponseErrorHandler errorHandler) {
        if (!(errorHandler instanceof OAuth2ErrorHandler)) {
            errorHandler = new OAuth2ErrorHandler(errorHandler, clientProperties);
        }
        super.setErrorHandler(errorHandler);
    }

    @Override
    protected ClientHttpRequest createRequest(URI uri, HttpMethod method) throws IOException {

        OAuth2AccessToken accessToken = clientContext.getAccessToken();
        if (accessToken == null) {
         throw new AccessTokenRequiredException(clientProperties);
        }

        AuthenticationScheme authenticationScheme = clientProperties.getAuthenticationScheme();
        if (AuthenticationScheme.query.equals(authenticationScheme)
                || AuthenticationScheme.form.equals(authenticationScheme)) {
            uri = appendQueryParameter(uri, accessToken);
        }

        ClientHttpRequest req = super.createRequest(uri, method);

        if (AuthenticationScheme.header.equals(authenticationScheme)) {


            authenticator.authenticate(clientProperties, clientContext, req);
        }
        return req;
    }

    @Override
    protected <T> T doExecute(URI url, HttpMethod method, RequestCallback requestCallback,
                              ResponseExtractor<T> responseExtractor) throws RestClientException {
        RuntimeException rethrow = null;
        try {
            return super.doExecute(url, method, requestCallback, responseExtractor);
        }
        catch (AccessTokenRequiredException e) {
            rethrow = e;
        }
        catch (OAuth2AccessDeniedException e) {
            rethrow = e;
        }
        catch (InvalidTokenException e) {
            // Don't reveal the token value in case it is logged
            rethrow = new OAuth2AccessDeniedException("Invalid token for tenant client=" + getClientId());
        }

        throw rethrow;
    }

    /**
     * @return the client id for this resource.
     */
    private String getClientId() {
        return clientProperties.getClientId();
    }

    protected URI appendQueryParameter(URI uri, OAuth2AccessToken accessToken) {
        try {

            // TODO: there is some duplication with UriUtils here. Probably unavoidable as long as this
            // method signature uses URI not String.
            String query = uri.getRawQuery(); // Don't decode anything here
            String queryFragment = clientProperties.getTokenName() + "=" + URLEncoder.encode(accessToken.getValue(), "UTF-8");
            if (query == null) {
                query = queryFragment;
            }
            else {
                query = query + "&" + queryFragment;
            }

            // first form the URI without query and fragment parts, so that it doesn't re-encode some query string chars
            // (SECOAUTH-90)
            URI update = new URI(uri.getScheme(), uri.getUserInfo(), uri.getHost(), uri.getPort(), uri.getPath(), null,
                    null);
            // now add the encoded query string and the then fragment
            StringBuffer sb = new StringBuffer(update.toString());
            sb.append("?");
            sb.append(query);
            if (uri.getFragment() != null) {
                sb.append("#");
                sb.append(uri.getFragment());
            }

            return new URI(sb.toString());

        }
        catch (URISyntaxException e) {
            throw new IllegalArgumentException("Could not parse URI", e);
        }
        catch (UnsupportedEncodingException e) {
            throw new IllegalArgumentException("Could not encode URI", e);
        }

    }

}
