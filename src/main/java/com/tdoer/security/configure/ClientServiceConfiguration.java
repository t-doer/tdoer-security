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

import com.tdoer.bedrock.service.ServiceType;
import com.tdoer.security.oauth2.client.CloudOAuth2ClientProperties;
import com.tdoer.security.oauth2.client.token.grant.code.AuthorizationCodeTokenTemplate;
import com.tdoer.security.oauth2.config.annotation.web.configurers.SsoSecurityConfigurer;
import org.aopalliance.intercept.MethodInterceptor;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.aop.framework.ProxyFactory;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ImportAware;
import org.springframework.core.type.AnnotationMetadata;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.util.ClassUtils;
import org.springframework.util.ReflectionUtils;

import java.lang.reflect.Method;

/**
 * @author Htinker Hu (htinker@163.com)
 * @create 2019-11-11
 */
@Configuration
public class ClientServiceConfiguration implements ImportAware, BeanPostProcessor, ApplicationContextAware {
    private Class<?> configType;

    private ServiceType serviceType;

    private ApplicationContext applicationContext;

    /**
     * From {@link com.tdoer.security.oauth2.config.annotation.web.configuration.OAuth2ClientConfiguration}
     */
    @Autowired
    private CloudOAuth2ClientProperties clientProperties;

    /**
     * From {@link com.tdoer.security.oauth2.config.annotation.web.configuration.OAuth2ClientConfiguration}
     */
    @Autowired
    protected AuthorizationCodeTokenTemplate tokenTemplate;

    /**
     * From Application
     */
    @Autowired
    protected ResourceServerTokenServices tokenServices;

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) {
        this.applicationContext = applicationContext;
    }

    @Override
    public void setImportMetadata(AnnotationMetadata importMetadata) {
        this.configType = ClassUtils.resolveClassName(importMetadata.getClassName(),
                null);
        if(importMetadata.hasAnnotation(EnableGatewayService.class.getName())){
            serviceType = ServiceType.GATEWAY;
        }else if(importMetadata.hasAnnotation(EnableBusinessService.class.getName())){
            serviceType = ServiceType.BUSINESS;
        }else if(importMetadata.hasAnnotation(EnableInfrastructureService.class.getName())){
            serviceType = ServiceType.INFRASTRUCTURE;
        }
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
            ProxyFactory factory = new ProxyFactory();
            factory.setTarget(bean);
            factory.addAdvice(new ServiceSecurityAdapter(serviceType, applicationContext));
            bean = factory.getProxy();
        }
        return bean;
    }

    private static class ServiceSecurityAdapter implements MethodInterceptor {

        private ClientServiceConfigurer clientServiceConfigurer;

        private SsoSecurityConfigurer ssoSecurityConfigurer;

        ServiceSecurityAdapter(ServiceType serviceType, ApplicationContext applicationContext) {
            this.clientServiceConfigurer = new ClientServiceConfigurer(applicationContext);
            if(serviceType == ServiceType.GATEWAY){
                ssoSecurityConfigurer = new SsoSecurityConfigurer(applicationContext);
            }
        }

        @Override
        public Object invoke(MethodInvocation invocation) throws Throwable {
            if (invocation.getMethod().getName().equals("init")) {
                Method method = ReflectionUtils
                        .findMethod(WebSecurityConfigurerAdapter.class, "getHttp");
                ReflectionUtils.makeAccessible(method);
                HttpSecurity http = (HttpSecurity) ReflectionUtils.invokeMethod(method,
                        invocation.getThis());
                if(ssoSecurityConfigurer != null){
                    ssoSecurityConfigurer.configure(http);
                }
                clientServiceConfigurer.configure(http);
            }
            return invocation.proceed();
        }

    }
}
