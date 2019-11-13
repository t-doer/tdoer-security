package com.tdoer.security.oauth2.client.token.grant.code;

import com.tdoer.security.oauth2.client.CloudOAuth2ClientProperties;
import com.tdoer.security.oauth2.client.CloudResourceDetailsFactory;
import com.tdoer.security.oauth2.client.token.AccessTokenRequestFactory;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.util.Assert;
import org.springframework.web.client.RestTemplate;

import javax.servlet.http.HttpServletRequest;

public class AuthorizationCodeTokenTemplate {

    protected CloudOAuth2ClientProperties clientProperties;

    protected CloudAuthorizationCodeTokenProvider tokenProvider;

    public AuthorizationCodeTokenTemplate(CloudOAuth2ClientProperties clientProperties, RestTemplate restTemplate){
        Assert.notNull(clientProperties, "ClientProperties cannot be null");
        Assert.notNull(restTemplate, "RestTemplate cannot be null");

        this.clientProperties = clientProperties;
        this.tokenProvider = new CloudAuthorizationCodeTokenProvider(restTemplate);
    }

    public OAuth2AccessToken obtainAccessToken(HttpServletRequest request){
        AuthorizationCodeResourceDetails resourceDetails = CloudResourceDetailsFactory.newAuthorizationCodeResourceDetails(clientProperties);
        AccessTokenRequest accessTokenRequest = AccessTokenRequestFactory.create(request);

        return tokenProvider.obtainAccessToken(resourceDetails, accessTokenRequest);
    }

    public OAuth2AccessToken refreshAccessToken(HttpServletRequest request, OAuth2RefreshToken refreshToken){
        AuthorizationCodeResourceDetails resourceDetails = CloudResourceDetailsFactory.newAuthorizationCodeResourceDetails(clientProperties);
        AccessTokenRequest accessTokenRequest = AccessTokenRequestFactory.create(request);
        return tokenProvider.refreshAccessToken(resourceDetails, refreshToken, accessTokenRequest);
    }

    public CloudOAuth2ClientProperties getClientProperties() {
        return clientProperties;
    }

    public CloudAuthorizationCodeTokenProvider getTokenProvider() {
        return tokenProvider;
    }
}
