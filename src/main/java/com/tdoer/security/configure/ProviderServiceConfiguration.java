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
package com.tdoer.security.configure;

import com.tdoer.bedrock.security.CloudWebAuthenticationDetailsSource;
import com.tdoer.security.oauth2.client.CloudOAuth2ClientProperties;
import com.tdoer.security.oauth2.common.token.TokenTemplate;
import com.tdoer.security.oauth2.provider.authentication.CheckUserStatusAuthenticationProvider;
import com.tdoer.security.oauth2.provider.authentication.OAuth2ProviderLogoutHandler;
import com.tdoer.security.oauth2.provider.authentication.OAuth2TokenAuthenticationSuccessHandler;
import com.tdoer.security.oauth2.provider.authentication.RequestTokenExtractor;
import com.tdoer.security.oauth2.provider.code.RedisAuthorizationCodeServices;
import com.tdoer.security.oauth2.provider.password.ResourceOwnerPasswordTokenGranter;
import com.tdoer.security.oauth2.provider.token.ProviderTokenTemplate;
import com.tdoer.security.oauth2.provider.token.RedisTokenServices;
import com.tdoer.security.oauth2.provider.token.store.redis.RedisTokenStore;
import com.tdoer.utils.cache.RedisJsonObjectOperator;
import org.aopalliance.aop.Advice;
import org.aopalliance.intercept.MethodInterceptor;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.aop.framework.ProxyFactory;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.annotation.*;
import org.springframework.core.type.AnnotationMetadata;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsChecker;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.CompositeTokenGranter;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.approval.ApprovalStore;
import org.springframework.security.oauth2.provider.approval.ApprovalStoreUserApprovalHandler;
import org.springframework.security.oauth2.provider.approval.TokenApprovalStore;
import org.springframework.security.oauth2.provider.approval.UserApprovalHandler;
import org.springframework.security.oauth2.provider.authentication.TokenExtractor;
import org.springframework.security.oauth2.provider.client.ClientCredentialsTokenGranter;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeTokenGranter;
import org.springframework.security.oauth2.provider.implicit.ImplicitTokenGranter;
import org.springframework.security.oauth2.provider.refresh.RefreshTokenGranter;
import org.springframework.security.oauth2.provider.request.DefaultOAuth2RequestFactory;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.util.ClassUtils;
import org.springframework.util.ReflectionUtils;

import javax.servlet.http.HttpServletRequest;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;

/**
 * Provider service configurtion depends on the properties and beans outside:
 *
 * <ul>
 *    <li>Application property: tdoer.auth.loginPage, which should be defined in application.yml</li>
 *    <li>Bean: org.springframework.data.redis.core.StringRedisTemplate, which is from
 *    com.tdoer.security.oauth2.config.annotation.configuration.ClientDetailsServiceConfiguration</li>
 *    <li>Bean: org.springframework.security.core.userdetails.UserDetailsService, which is from application's
 *    component scan</li>
 *    <li>Bean: org.springframework.security.authentication.AuthenticationManager, which is from application's
 *    component scan</li>
 * </ul>
 *
 * @author Htinker Hu (htinker@163.com)
 * @create 2019-11-11
 */
@Configuration
public class ProviderServiceConfiguration implements ImportAware, BeanPostProcessor, ApplicationContextAware {
    private Class<?> configType;

    private ApplicationContext applicationContext;

    @Value("${tdoer.auth.loginPage}")
    private String loginPage;

    // Needed by {@link ProviderServiceConfigurer}
    @ConfigurationProperties(prefix = "security.oauth2.client")
    @Bean
    public CloudOAuth2ClientProperties cloudOAuth2ClientProperties(){
        return new CloudOAuth2ClientProperties();
    }

    // StringRedisTemplate is from auto config of spring-boot-starter-data-redis
    @Bean
    public RedisJsonObjectOperator redisJsonObjectOperator(StringRedisTemplate stringRedisTemplate){
        return new RedisJsonObjectOperator(stringRedisTemplate);
    }

    // Needed by {@link AuthorizationServerConfiguration}
    @Bean
    public RedisTokenStore tokenStore(RedisJsonObjectOperator redisJsonObjectOperator){
        return new RedisTokenStore(redisJsonObjectOperator);
    }

    @Bean
    @Lazy
    public ApprovalStore approvalStore(RedisTokenStore tokenStore) throws Exception {
        TokenApprovalStore store = new TokenApprovalStore();
        store.setTokenStore(tokenStore);
        return store;
    }

    // Needed by {@link AuthorizationServerConfiguration}
    @Bean
    public AuthorizationCodeServices authorizationCodeServices(RedisJsonObjectOperator redisJsonObjectOperator){
        return new RedisAuthorizationCodeServices(redisJsonObjectOperator);
    }

    // Needed by {@link AuthorizationServerConfiguration}
    @Bean
    public OAuth2RequestFactory requestFactory(ClientDetailsService clientDetailsService){
        // We can customize OAuth2RequestFactory to create customized OAuth2Requests
        return new DefaultOAuth2RequestFactory(clientDetailsService);
    }

    // Needed by {@link AuthorizationServerConfiguration}
    @Bean
    @Lazy
    @Scope(proxyMode = ScopedProxyMode.TARGET_CLASS)
    public UserApprovalHandler userApprovalHandler(ApprovalStore approvalStore,
                                                   OAuth2RequestFactory requestFactory,
                                                   ClientDetailsService clientDetailsService) throws Exception {
        ApprovalStoreUserApprovalHandler handler = new ApprovalStoreUserApprovalHandler();
        handler.setApprovalStore(approvalStore);
        handler.setRequestFactory(requestFactory);
        handler.setClientDetailsService(clientDetailsService);
        return handler;
    }

    // Needed by {@link AuthorizationServerConfiguration}
    // Needed by {@link ProviderServiceConfigurer}
    @Bean
    public RedisTokenServices redisTokenServices(RedisTokenStore tokenStore,
                                                 ClientDetailsService clientDetailsService,
                                                 UserDetailsService userDetailsService) {

        RedisTokenServices tokenServices = new RedisTokenServices();
        tokenServices.setTokenStore(tokenStore);
        tokenServices.setSupportRefreshToken(true);
        tokenServices.setReuseRefreshToken(false);
        tokenServices.setClientDetailsService(clientDetailsService);

        // AuthenticationProvider for refresh access token
        UserDetailsChecker userDetailsChecker = new AccountStatusUserDetailsChecker();
        CheckUserStatusAuthenticationProvider authenticationProvider =
                new CheckUserStatusAuthenticationProvider(userDetailsService, userDetailsChecker);
        AuthenticationManager authenticationManager = new ProviderManager(Arrays.asList(authenticationProvider));

        tokenServices.setAuthenticationManager(authenticationManager);

        return tokenServices;
    }

    // Needed by {@link AuthorizationServerConfiguration}
    @Bean
    public TokenGranter tokenGranter(RedisTokenServices redisTokenServices,
                                     AuthorizationCodeServices authorizationCodeServices,
                                     ClientDetailsService clientDetailsService,
                                     OAuth2RequestFactory requestFactory,
                                     AuthenticationManager authenticationManager // check user/password
                                     ){
        ArrayList<TokenGranter> tokenGranters = new ArrayList<>(5);
        tokenGranters.add(new AuthorizationCodeTokenGranter(redisTokenServices, authorizationCodeServices, clientDetailsService, requestFactory));
        tokenGranters.add(new RefreshTokenGranter(redisTokenServices, clientDetailsService, requestFactory));
        tokenGranters.add(new ImplicitTokenGranter(redisTokenServices, clientDetailsService, requestFactory));
        tokenGranters.add(new ClientCredentialsTokenGranter(redisTokenServices, clientDetailsService, requestFactory));
        tokenGranters.add(new ResourceOwnerPasswordTokenGranter(authenticationManager, redisTokenServices, clientDetailsService,
                requestFactory));

        return new CompositeTokenGranter(tokenGranters);
    }

    // Needed by {@link ProviderServiceConfigurer}
    @Bean
    public AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource(){
        return new CloudWebAuthenticationDetailsSource();
    }

    // Needed by {@link ProviderServiceConfigurer}
    @Bean
    public TokenTemplate tokenTemplate(CloudOAuth2ClientProperties clientProperties, OAuth2RequestFactory requestFactory,
                                       TokenGranter tokenGranter){
        return new ProviderTokenTemplate(clientProperties, requestFactory, tokenGranter);
    }

    @Bean
    public TokenExtractor tokenExtractor(){
        return new RequestTokenExtractor();
    }

    // Needed by {@link ProviderServiceConfigurer}
    @Bean
    public OAuth2ProviderLogoutHandler logoutHandler(RedisTokenServices redisTokenServices) {
        OAuth2ProviderLogoutHandler handler = new OAuth2ProviderLogoutHandler();
        handler.setTokenServices(redisTokenServices);
        return handler;
    }

    // Needed by {@link ProviderServiceConfigurer}
    @Bean
    public OAuth2TokenAuthenticationSuccessHandler auth2TokenAuthenticationSuccessHandler(
            CloudOAuth2ClientProperties clientProperties,
            ClientDetailsService clientDetailsService,
            OAuth2RequestFactory requestFactory,
            RedisTokenServices redisTokenServices){
        OAuth2TokenAuthenticationSuccessHandler successHandler = new OAuth2TokenAuthenticationSuccessHandler(clientProperties);
        successHandler.setTargetUrlParameter("redirect_uri");
        successHandler.setClientDetailsService(clientDetailsService);
        successHandler.setRequestFactory(requestFactory);
        successHandler.setTokenServices(redisTokenServices);
        return successHandler;
    }

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) {
        this.applicationContext = applicationContext;
    }

    @Override
    public void setImportMetadata(AnnotationMetadata importMetadata) {
        this.configType = ClassUtils.resolveClassName(importMetadata.getClassName(),
                null);
    }

    @Override
    public Object postProcessBeforeInitialization(Object bean, String beanName)
            throws BeansException {
        return bean;
    }

    @Override
    public Object postProcessAfterInitialization(Object bean, String beanName)
            throws BeansException {
        if (this.configType.isAssignableFrom(bean.getClass())
                && bean instanceof WebSecurityConfigurerAdapter) {

            Advice advice = new ServiceSecurityAdapter(loginPage, applicationContext);

            ProxyFactory factory = new ProxyFactory();
            factory.setTarget(bean);
            factory.addAdvice(advice);
            bean = factory.getProxy();
        }
        return bean;
    }

    private static class ServiceSecurityAdapter implements MethodInterceptor {

        private ProviderServiceConfigurer configurer;

        ServiceSecurityAdapter(String loginPage,
                               ApplicationContext applicationContext) {

            this.configurer = new ProviderServiceConfigurer(loginPage, applicationContext);
        }

        @Override
        public Object invoke(MethodInvocation invocation) throws Throwable {
            if (invocation.getMethod().getName().equals("init")) {
                Method method = ReflectionUtils
                        .findMethod(WebSecurityConfigurerAdapter.class, "getHttp");
                ReflectionUtils.makeAccessible(method);
                HttpSecurity http = (HttpSecurity) ReflectionUtils.invokeMethod(method,
                        invocation.getThis());
                this.configurer.configure(http);
            }
            return invocation.proceed();
        }

    }
}
