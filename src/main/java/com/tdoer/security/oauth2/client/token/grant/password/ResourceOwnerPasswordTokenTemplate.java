package com.tdoer.security.oauth2.client.token.grant.password;

import com.tdoer.security.oauth2.client.CloudOAuth2ClientProperties;
import com.tdoer.security.oauth2.client.CloudResourceDetailsFactory;
import com.tdoer.security.oauth2.client.token.AccessTokenRequestFactory;
import com.tdoer.security.oauth2.common.token.RefreshableTokenTemplate;
import com.tdoer.springboot.util.WebUtil;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordResourceDetails;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.util.Assert;
import org.springframework.web.client.RestTemplate;

import javax.servlet.http.HttpServletRequest;

public class ResourceOwnerPasswordTokenTemplate implements RefreshableTokenTemplate {

    protected CloudOAuth2ClientProperties clientProperties;

    protected CloudUserPasswordTokenProvider tokenProvider;

    public ResourceOwnerPasswordTokenTemplate(CloudOAuth2ClientProperties clientProperties, RestTemplate restTemplate){
        Assert.notNull(clientProperties, "ClientProperties cannot be null");
        Assert.notNull(restTemplate, "RestTemplate cannot be null");

        this.clientProperties = clientProperties;
        this.tokenProvider = new CloudUserPasswordTokenProvider(restTemplate);
    }

    @Override
    public OAuth2AccessToken createAccessToken(HttpServletRequest request){
        String username = WebUtil.findValueFromRequest(request, "username");
        String password = WebUtil.findValueFromRequest(request, "password");

        Assert.hasText(username, "Username cannot be blank");
        Assert.hasText(password, "Password cannot be blank");

        ResourceOwnerPasswordResourceDetails resourceDetails =
                CloudResourceDetailsFactory.newResourceOwnerPasswordResourceDetails(clientProperties, username, password);
        AccessTokenRequest accessTokenRequest = AccessTokenRequestFactory.create(request);

        return tokenProvider.obtainAccessToken(resourceDetails, accessTokenRequest);
    }

    @Override
    public OAuth2AccessToken refreshAccessToken(HttpServletRequest request, OAuth2RefreshToken refreshToken){
        ResourceOwnerPasswordResourceDetails resourceDetails = CloudResourceDetailsFactory.newResourceOwnerPasswordResourceDetails(clientProperties, "", "");
        AccessTokenRequest accessTokenRequest = AccessTokenRequestFactory.create(request);
        return tokenProvider.refreshAccessToken(resourceDetails, refreshToken, accessTokenRequest);
    }

    @Override
    public CloudOAuth2ClientProperties getClientProperties() {
        return clientProperties;
    }

    public CloudUserPasswordTokenProvider getTokenProvider() {
        return tokenProvider;
    }
}
