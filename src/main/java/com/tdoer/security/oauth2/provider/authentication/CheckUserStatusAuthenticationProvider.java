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
package com.tdoer.security.oauth2.provider.authentication;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsChecker;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.util.Assert;

/**
 * @author Htinker Hu (htinker@163.com)
 * @create 2019-11-19
 */
public class CheckUserStatusAuthenticationProvider implements AuthenticationProvider,
        InitializingBean {

    private static Logger logger = LoggerFactory.getLogger(CheckUserStatusAuthenticationProvider.class);

    private boolean throwExceptionWhenTokenRejected = false;

    private UserDetailsService userDetailsService;

    private UserDetailsChecker userDetailsChecker;

    public CheckUserStatusAuthenticationProvider(UserDetailsService userDetailsService, UserDetailsChecker userDetailsChecker) {
        Assert.notNull(userDetailsService, "UserDetailsService cannot be null");
        Assert.notNull(userDetailsChecker, "UserDetailsChecker cannot be null");

        this.userDetailsService = userDetailsService;
        this.userDetailsChecker = userDetailsChecker;
    }

    @Override
    public void afterPropertiesSet() throws Exception {

    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        if (!supports(authentication.getClass())) {
            return null;
        }

        if (logger.isDebugEnabled()) {
            logger.debug("PreAuthenticated authentication request: " + authentication);
        }

        if (authentication.getPrincipal() == null) {
            logger.debug("No pre-authenticated principal found in request.");

            if (throwExceptionWhenTokenRejected) {
                throw new BadCredentialsException(
                        "No pre-authenticated principal found in request.");
            }
            return null;
        }

        if (authentication.getCredentials() == null) {
            logger.debug("No pre-authenticated credentials found in request.");

            if (throwExceptionWhenTokenRejected) {
                throw new BadCredentialsException(
                        "No pre-authenticated credentials found in request.");
            }
            return null;
        }

        UserDetails ud = userDetailsService.loadUserByUsername(authentication.getName());

        userDetailsChecker.check(ud);

        return authentication;
    }

    /**
     * Indicate that this provider only supports PreAuthenticatedAuthenticationToken
     * (sub)classes.
     * @param authentication
     * @return
     */
    @Override
    public boolean supports(Class<?> authentication) {
        return PreAuthenticatedAuthenticationToken.class.isAssignableFrom(authentication);
    }

    /**
     * If true, causes the provider to throw a BadCredentialsException if the presented
     * authentication request is invalid (contains a null principal or credentials).
     * Otherwise it will just return null. Defaults to false.
     */
    public void setThrowExceptionWhenTokenRejected(boolean throwExceptionWhenTokenRejected) {
        this.throwExceptionWhenTokenRejected = throwExceptionWhenTokenRejected;
    }
}
