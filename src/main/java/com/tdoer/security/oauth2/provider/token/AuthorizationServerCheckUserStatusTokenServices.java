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
package com.tdoer.security.oauth2.provider.token;

import com.tdoer.bedrock.security.UserDetails;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsChecker;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.util.Assert;

/**
 * @author Htinker Hu (htinker@163.com)
 * @create 2017-09-19
 */
public class AuthorizationServerCheckUserStatusTokenServices implements ResourceServerTokenServices, ReadingRefreshTokenServices {
    private RedisTokenServices redisTokenServices;

    private UserDetailsService userDetailsService;

    private UserDetailsChecker userDetailsChecker;

    public AuthorizationServerCheckUserStatusTokenServices(RedisTokenServices redisTokenServices, UserDetailsService userDetailsService) {
        Assert.notNull(redisTokenServices, "RedisTokenService cannot be null");
        Assert.notNull(userDetailsService, "UserDetailsService cannot be null");

        this.redisTokenServices = redisTokenServices;
        this.userDetailsService = userDetailsService;
        userDetailsChecker = new AccountStatusUserDetailsChecker();
    }

    /**
     * Load the credentials for the specified access token.
     *
     * @param accessToken The access token value.
     * @return The authentication for the access token.
     * @throws AuthenticationException If the access token is expired
     * @throws InvalidTokenException   if the token isn't valid
     */
    @Override
    public OAuth2Authentication loadAuthentication(String accessToken) throws AuthenticationException, InvalidTokenException {
        OAuth2Authentication storedAuth = redisTokenServices.loadAuthentication(accessToken);

        UserDetails user = (UserDetails) userDetailsService.loadUserByUsername(storedAuth.getName());
        if(user == null || user.getUser() == null){
            throw new InvalidTokenException("User not found");
        }


        userDetailsChecker.check(user);

        return storedAuth;
    }

    /**
     * Retrieve the full access token details from just the value.
     *
     * @param accessToken the token value
     * @return the full access token with client id etc.
     */
    @Override
    public OAuth2AccessToken readAccessToken(String accessToken) {
        return redisTokenServices.readAccessToken(accessToken);
    }

    @Override
    public OAuth2RefreshToken readRefreshTokenForToken(String tokenValue) {
        return redisTokenServices.readRefreshTokenForToken(tokenValue);
    }
}
