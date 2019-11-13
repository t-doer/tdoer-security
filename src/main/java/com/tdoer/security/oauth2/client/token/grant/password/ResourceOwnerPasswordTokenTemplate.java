package com.tdoer.security.oauth2.client.token.grant.password;

import com.tdoer.security.oauth2.client.CloudOAuth2ClientProperties;
import com.tdoer.security.oauth2.client.CloudResourceDetailsFactory;
import com.tdoer.security.oauth2.client.token.AccessTokenRequestFactory;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordResourceDetails;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.util.Assert;
import org.springframework.web.client.RestTemplate;

import javax.servlet.http.HttpServletRequest;

public class ResourceOwnerPasswordTokenTemplate {

    protected CloudOAuth2ClientProperties clientProperties;

    protected CloudUserPasswordTokenProvider tokenProvider;

    public ResourceOwnerPasswordTokenTemplate(CloudOAuth2ClientProperties clientProperties, RestTemplate restTemplate){
        Assert.notNull(clientProperties, "ClientProperties cannot be null");
        Assert.notNull(restTemplate, "RestTemplate cannot be null");

        this.clientProperties = clientProperties;
        this.tokenProvider = new CloudUserPasswordTokenProvider(restTemplate);
    }

    public OAuth2AccessToken obtainAccessToken(HttpServletRequest request, String login, String password){
        Assert.hasText(login, "Login cannot be blank");
        Assert.hasText(password, "Password cannot be blank");

        ResourceOwnerPasswordResourceDetails resourceDetails = CloudResourceDetailsFactory.newResourceOwnerPasswordResourceDetails(clientProperties, login, password);
        AccessTokenRequest accessTokenRequest = AccessTokenRequestFactory.create(request);

        return tokenProvider.obtainAccessToken(resourceDetails, accessTokenRequest);
    }

    public OAuth2AccessToken refreshAccessToken(HttpServletRequest request, OAuth2RefreshToken refreshToken){
        ResourceOwnerPasswordResourceDetails resourceDetails = CloudResourceDetailsFactory.newResourceOwnerPasswordResourceDetails(clientProperties, "", "");
        AccessTokenRequest accessTokenRequest = AccessTokenRequestFactory.create(request);
        return tokenProvider.refreshAccessToken(resourceDetails, refreshToken, accessTokenRequest);
    }

    public CloudOAuth2ClientProperties getClientProperties() {
        return clientProperties;
    }

    public CloudUserPasswordTokenProvider getTokenProvider() {
        return tokenProvider;
    }
}
