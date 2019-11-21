package com.tdoer.security.configure;

import com.tdoer.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import com.tdoer.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import com.tdoer.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import com.tdoer.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import com.tdoer.security.oauth2.provider.endpoint.TrustRedirectResolver;
import com.tdoer.security.oauth2.provider.token.RedisTokenServices;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.approval.UserApprovalHandler;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.util.Assert;

/**
 * The config class is to configure OAuth 2.0 AuthorizationServer which will protect
 * the endpoints below. A request to access the endpoints, its request header must contain
 * valid basic authentication info of client Id / client secret.
 *
 * <ul>
 *     <li>/oauth/token</li>
 *     <li>/oauth/token_key</li>
 *     <li>/oauth/check_token</li>
 * </ul>
 */
@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfiguration extends AuthorizationServerConfigurerAdapter implements InitializingBean {

    /**
     * From {@link ProviderServiceConfiguration}
     */
    @Autowired
    private TokenGranter tokenGranter;

    /**
     * From {@link ProviderServiceConfiguration}
     */
    @Autowired
    private TokenStore tokenStore;

    /**
     * From {@link ProviderServiceConfiguration}
     */
    @Autowired
    private RedisTokenServices redisTokenServices;

    /**
     * From {@link ProviderServiceConfiguration}
     */
    @Autowired
    private UserApprovalHandler userApprovalHandler;

    /**
     * From {@link ProviderServiceConfiguration}
     */
    @Autowired
    private OAuth2RequestFactory requestFactory;

    /**
     * From {@link ProviderServiceConfiguration}
     */
    @Autowired
    private AuthorizationCodeServices authorizationCodeServices;

    @Override
    public void afterPropertiesSet() throws Exception {
        Assert.notNull(tokenGranter, "TokenGranter is required");
        Assert.notNull(tokenStore, "TokenStore is required");
        Assert.notNull(redisTokenServices, "RedisTokenServices is required");
        Assert.notNull(userApprovalHandler, "UserApprovalHandler is required");
        Assert.notNull(requestFactory, "OAuth2RequestFactory is required");
        Assert.notNull(authorizationCodeServices, "AuthorizationCodeServices is required");
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {

        endpoints
                .tokenGranter(tokenGranter)
                .tokenStore(tokenStore)
                .tokenServices(redisTokenServices)
                .userApprovalHandler(userApprovalHandler)
                .requestFactory(requestFactory)
                .redirectResolver(new TrustRedirectResolver())
                .authorizationCodeServices(authorizationCodeServices);
    }

    @Override
    public void configure(AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
        oauthServer.tokenKeyAccess("hasRole('CLIENT')")
                .checkTokenAccess("hasRole('CLIENT')")
                .realm("oauth/client");
    }
}
