package com.tdoer.security.oauth2.client.token.grant.client;

import com.tdoer.security.oauth2.client.CloudOAuth2ClientProperties;
import com.tdoer.security.oauth2.client.CloudResourceDetailsFactory;
import com.tdoer.security.oauth2.client.token.AccessTokenRequestFactory;
import com.tdoer.security.oauth2.common.token.TokenTemplate;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsResourceDetails;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.util.Assert;
import org.springframework.web.client.RestTemplate;

import javax.servlet.http.HttpServletRequest;

public class ClientCredentialsTokenTemplate implements TokenTemplate {
    protected CloudOAuth2ClientProperties clientProperties;

    protected CloudClientCredentialsTokenProvider tokenProvider;

    public ClientCredentialsTokenTemplate(CloudOAuth2ClientProperties clientProperties, RestTemplate restTemplate){
        Assert.notNull(clientProperties, "ClientProperties cannot be null");
        Assert.notNull(restTemplate, "RestTemplate cannot be null");

        this.clientProperties = clientProperties;
        this.tokenProvider = new CloudClientCredentialsTokenProvider(restTemplate);
    }

    @Override
    public OAuth2AccessToken createAccessToken(HttpServletRequest request){
        ClientCredentialsResourceDetails resourceDetails = CloudResourceDetailsFactory.newClientCredentialsResourceDetails(clientProperties);
        AccessTokenRequest accessTokenRequest = AccessTokenRequestFactory.create(request);

        return tokenProvider.obtainAccessToken(resourceDetails, accessTokenRequest);
    }

    @Override
    public CloudOAuth2ClientProperties getClientProperties() {
        return clientProperties;
    }

    public CloudClientCredentialsTokenProvider getTokenProvider() {
        return tokenProvider;
    }
}
