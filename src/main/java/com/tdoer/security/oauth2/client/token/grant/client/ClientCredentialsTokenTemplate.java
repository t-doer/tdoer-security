package com.tdoer.security.oauth2.client.token.grant.client;

import com.tdoer.security.oauth2.client.CloudOAuth2ClientProperties;
import com.tdoer.security.oauth2.client.CloudResourceDetailsFactory;
import com.tdoer.security.oauth2.client.token.AccessTokenRequestFactory;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsResourceDetails;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.util.Assert;
import org.springframework.web.client.RestTemplate;

import javax.servlet.http.HttpServletRequest;

public class ClientCredentialsTokenTemplate {
    protected CloudOAuth2ClientProperties clientProperties;

    protected CloudClientCredentialsTokenProvider tokenProvider;

    public ClientCredentialsTokenTemplate(CloudOAuth2ClientProperties clientProperties, RestTemplate restTemplate){
        Assert.notNull(clientProperties, "ClientProperties cannot be null");
        Assert.notNull(restTemplate, "RestTemplate cannot be null");

        this.clientProperties = clientProperties;
        this.tokenProvider = new CloudClientCredentialsTokenProvider(restTemplate);
    }

    public OAuth2AccessToken obtainAccessToken(HttpServletRequest request){
        ClientCredentialsResourceDetails resourceDetails = CloudResourceDetailsFactory.newClientCredentialsResourceDetails(clientProperties);
        AccessTokenRequest accessTokenRequest = AccessTokenRequestFactory.create(request);

        return tokenProvider.obtainAccessToken(resourceDetails, accessTokenRequest);
    }

    public CloudOAuth2ClientProperties getClientProperties() {
        return clientProperties;
    }

    public CloudClientCredentialsTokenProvider getTokenProvider() {
        return tokenProvider;
    }
}
