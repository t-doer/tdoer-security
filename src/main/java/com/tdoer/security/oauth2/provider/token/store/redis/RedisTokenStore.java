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
package com.tdoer.security.oauth2.provider.token.store.redis;

import com.tdoer.bedrock.Platform;
import com.tdoer.security.oauth2.util.OAuth2AuthenticationUtil;
import com.tdoer.utils.cache.RedisJsonObjectOperator;
import org.springframework.security.oauth2.common.ExpiringOAuth2RefreshToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.AuthenticationKeyGenerator;
import org.springframework.security.oauth2.provider.token.DefaultAuthenticationKeyGenerator;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.util.Assert;

import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Set;

/**
 * Copy and modify {@link org.springframework.security.oauth2.provider.token.store.redis.RedisTokenStore},
 * to store "appid:login:useragent" related records for user login session management. Likai Hu, 2018/10/13.
 *
 * @author Htinker Hu (htinker@163.com)
 * @create 2017-09-19
 */
public class RedisTokenStore implements TokenStore {

    // key prefixes
	private static final String TOKEN_TO_TOKEN_OBJ = "token_to_token_obj:"; // prefix for token to OAuth2AccessToken
    private static final String TOKEN_TO_AUTH_OBJ = "token_to_auth_obj:"; // prefix for token to OAuth2Authentication
    private static final String TOKEN_TO_REFRESH_TOKEN = "token_to_refresh_token:"; // prefix for token to refresh token
    private static final String REFRESH_TOKEN_TO_TOKEN = "refresh_token_to_token:"; // prefix for refresh token to access token
    private static final String REFRESH_TOKEN_TO_REFRESH_TOKEN_OBJ = "refresh_token_to_refresh_token_obj:"; // prefix for refresh token to OAuth2RefreshToken_
    private static final String REFRESH_TOKEN_TO_AUTH_OBJ = "refresh_token_to_auth_obj:"; // prefix for refresh token to OAuth2Authentication
    private static final String AUTH_KEY_TO_TOKEN_OBJ = "auth_key_to_token_obj:"; // prefix for authentication key to OAuth2AccessToken

    /* ---------------------------------------------------------------------------
     * Part I: Private attributes and preparation
     * ----------------------------------------------------------------------------
     */

    private RedisJsonObjectOperator redisOperator;

	private AuthenticationKeyGenerator authenticationKeyGenerator;

	private String prefix = "auth:";

	public RedisTokenStore(RedisJsonObjectOperator redisOperator) {
        Assert.notNull(redisOperator, "RedisJsonObjectOperator cannot be null");
	    this.authenticationKeyGenerator = new DefaultAuthenticationKeyGenerator();
	    this.redisOperator = redisOperator;
	}


	public void setAuthenticationKeyGenerator(DefaultAuthenticationKeyGenerator authenticationKeyGenerator) {
		this.authenticationKeyGenerator = authenticationKeyGenerator;
	}

	public void setPrefix(String prefix) {
		this.prefix = prefix;
	}

    /* ---------------------------------------------------------------------------
     * Part II: Keys
     * ----------------------------------------------------------------------------
     */

    protected String getKeyPrefix(){
        return Platform.getCurrentEnvironment().getTenantId() + ":" + prefix;
    }

    protected String getKeyOfToken2TokenObj(String token){
        return getKeyPrefix() + TOKEN_TO_TOKEN_OBJ + token;
    }

    protected String getKeyOfToken2AuthenticationObj(String token){
        return getKeyPrefix() + TOKEN_TO_AUTH_OBJ + token;
    }

    protected String getKeyOfToken2RefreshToken(String token){
        return getKeyPrefix() + TOKEN_TO_REFRESH_TOKEN + token;
    }

    protected String getKeyOfRefreshToken2AuthenticationObj(String token){
        return getKeyPrefix() + REFRESH_TOKEN_TO_AUTH_OBJ + token;
    }

    protected String getKeyOfRefreshToken2Token(String refreshToken){
        return getKeyPrefix() + REFRESH_TOKEN_TO_TOKEN + refreshToken;
    }

    protected String getKeyOfRefreshToken2RefreshTokenObj(String refreshToken){
        return getKeyPrefix() + REFRESH_TOKEN_TO_REFRESH_TOKEN_OBJ + refreshToken;
    }

    protected String getKeyOfAuthKey2TokenObj(OAuth2Authentication authentication){
        return getKeyPrefix() + AUTH_KEY_TO_TOKEN_OBJ + authenticationKeyGenerator.extractKey(authentication);
    }

    protected String getKeyOfApprovalKey2TokenSet(OAuth2Authentication authentication) {
        String userName = OAuth2AuthenticationUtil.getUserName(authentication);
        String clientId = OAuth2AuthenticationUtil.getClientId(authentication);
        return getKeyOfApprovalKey2TokenSet(clientId, userName);
    }

    protected String getKeyOfApprovalKey2TokenSet(String clientId, String userName) {
        return getKeyPrefix() + clientId + (userName == null ? "" : ":" + userName);
    }

    /* ---------------------------------------------------------------------------
     * Part III: Interface methods
     * ----------------------------------------------------------------------------
     */
    @Override
    public void storeAccessToken(OAuth2AccessToken token, OAuth2Authentication authentication) {
        // token string - OAuth2AccessToken
        redisOperator.setObject(getKeyOfToken2TokenObj(token.getValue()), token, token.getExpiresIn());

        // token string - OAuth2Authentication
        redisOperator.setObject(getKeyOfToken2AuthenticationObj(token.getValue()), authentication, token.getExpiresIn());

        // auth key - OAuth2AccessToken
        redisOperator.setObject(getKeyOfAuthKey2TokenObj(authentication), token, token.getExpiresIn());

        if(!authentication.isClientOnly()){
            // approval key - OAuth2Authentication (in a set)
            redisOperator.setAddObject(getKeyOfApprovalKey2TokenSet(authentication), token);
            redisOperator.expire(getKeyOfApprovalKey2TokenSet(authentication), token.getExpiresIn());
        }

        OAuth2RefreshToken refreshToken = token.getRefreshToken();
        if (refreshToken != null && refreshToken.getValue() != null) {
            int expiredInSeconds = getExpiredInSeconds(refreshToken);

            if(expiredInSeconds == -1){
                // token - refresh token
                redisOperator.set(getKeyOfToken2RefreshToken(token.getValue()), refreshToken.getValue());
                // refresh token - token
                redisOperator.set(getKeyOfRefreshToken2Token(refreshToken.getValue()), token.getValue());
            }else{
                // token - refresh token
                redisOperator.set(getKeyOfToken2RefreshToken(token.getValue()), refreshToken.getValue(), expiredInSeconds);
                // refresh token - token
                redisOperator.set(getKeyOfRefreshToken2Token(refreshToken.getValue()), token.getValue(), expiredInSeconds);
            }
        }
    }

    @Override
    public void removeAccessToken(OAuth2AccessToken accessToken) {
        removeAccessToken(accessToken.getValue());
    }

    public void removeAccessToken(String token) {
        redisOperator.delete(getKeyOfToken2TokenObj(token));
        redisOperator.delete(getKeyOfToken2AuthenticationObj(token));

        OAuth2Authentication authentication = readAuthentication(token);
        if(authentication != null){
            redisOperator.delete(getKeyOfAuthKey2TokenObj(authentication));
            redisOperator.setRemoveObject(getKeyOfApprovalKey2TokenSet(authentication),authentication);
        }

        String refreshToken = redisOperator.get(getKeyOfToken2RefreshToken(token));
        if(refreshToken != null){
            removeRefreshToken(refreshToken);
        }
    }

    @Override
    public void storeRefreshToken(OAuth2RefreshToken refreshToken, OAuth2Authentication authentication) {

        int expiredInSeconds = getExpiredInSeconds(refreshToken);

        if(expiredInSeconds == -1){
            // refresh token  - OAuth2RefreshToken
            redisOperator.setObject(getKeyOfRefreshToken2RefreshTokenObj(refreshToken.getValue()), refreshToken);
            // refresh token - OAuth2Authentication
            redisOperator.setObject(getKeyOfRefreshToken2AuthenticationObj(refreshToken.getValue()), authentication);
        }else{
            // refresh token  - OAuth2RefreshToken
            redisOperator.setObject(getKeyOfRefreshToken2RefreshTokenObj(refreshToken.getValue()), refreshToken, expiredInSeconds);
            // refresh token - OAuth2Authentication
            redisOperator.setObject(getKeyOfRefreshToken2AuthenticationObj(refreshToken.getValue()), authentication, expiredInSeconds);
        }
    }

    @Override
    public void removeRefreshToken(OAuth2RefreshToken refreshToken) {
        removeRefreshToken(refreshToken.getValue());
    }

    public void removeRefreshToken(String refreshToken) {
        String token = redisOperator.get(getKeyOfRefreshToken2Token(refreshToken));

        redisOperator.delete(getKeyOfRefreshToken2RefreshTokenObj(refreshToken));
        redisOperator.delete(getKeyOfRefreshToken2AuthenticationObj(refreshToken));
        redisOperator.delete(getKeyOfRefreshToken2Token(refreshToken));
        if(token != null){
            redisOperator.delete(getKeyOfToken2RefreshToken(token));
        }
    }

    @Override
    public void removeAccessTokenUsingRefreshToken(OAuth2RefreshToken refreshToken) {
        removeAccessTokenUsingRefreshToken(refreshToken.getValue());
    }

    private void removeAccessTokenUsingRefreshToken(String refreshToken) {
        String accessToken = redisOperator.get(getKeyOfRefreshToken2Token(refreshToken));
        if (accessToken != null) {
            removeAccessToken(accessToken);
        }
    }

    protected int getExpiredInSeconds(OAuth2RefreshToken refreshToken){
        int expiredInSeconds = -1;

        if (refreshToken instanceof ExpiringOAuth2RefreshToken) {
            ExpiringOAuth2RefreshToken expiringRefreshToken = (ExpiringOAuth2RefreshToken) refreshToken;
            Date expiration = expiringRefreshToken.getExpiration();
            if (expiration != null) {
                expiredInSeconds = Long.valueOf((expiration.getTime() - System.currentTimeMillis()) / 1000L).intValue();
            }
        }
        return expiredInSeconds;
    }


	@Override
	public OAuth2Authentication readAuthentication(OAuth2AccessToken token) {
		return readAuthentication(token.getValue());
	}

	@Override
	public OAuth2Authentication readAuthentication(String token) {
		return redisOperator.getObject(getKeyOfToken2AuthenticationObj(token), OAuth2Authentication.class);
	}

	@Override
	public OAuth2Authentication readAuthenticationForRefreshToken(OAuth2RefreshToken refreshToken) {
		return readAuthenticationForRefreshToken(refreshToken.getValue());
	}

	public OAuth2Authentication readAuthenticationForRefreshToken(String refreshToken) {
        return redisOperator.getObject(getKeyOfRefreshToken2AuthenticationObj(refreshToken),OAuth2Authentication.class);
	}

	@Override
	public OAuth2AccessToken readAccessToken(String token) {
		return redisOperator.getObject(getKeyOfToken2TokenObj(token), OAuth2AccessToken.class);
	}

	@Override
	public OAuth2RefreshToken readRefreshToken(String refreshToken) {
        return redisOperator.getObject(getKeyOfRefreshToken2RefreshTokenObj(refreshToken), OAuth2RefreshToken.class);
	}

	public String readRefreshTokenValueForToken(String tokenValue){
		return redisOperator.get(getKeyOfToken2RefreshToken(tokenValue));
	}

	public OAuth2RefreshToken readRefreshTokenForToken(String tokenValue){
	    String refreshTokenValue = readRefreshTokenValueForToken(tokenValue);
	    if(refreshTokenValue != null){
	        return readRefreshToken(refreshTokenValue);
        }
        return null;
    }

	@Override
	public Collection<OAuth2AccessToken> findTokensByClientIdAndUserName(String clientId, String userName) {
		Set<OAuth2AccessToken> set = redisOperator.setGetObjects(getKeyOfApprovalKey2TokenSet(clientId, userName), OAuth2AccessToken.class);
		return Collections.unmodifiableCollection(set);
	}


	@Override
	public Collection<OAuth2AccessToken> findTokensByClientId(String clientId) {
        throw new UnsupportedOperationException("The method is not supported");
	}

    @Override
    public OAuth2AccessToken getAccessToken(OAuth2Authentication authentication) {
        String key = getKeyOfAuthKey2TokenObj(authentication);
        OAuth2AccessToken accessToken = redisOperator.getObject(key, OAuth2AccessToken.class);
        if (accessToken != null) {
            OAuth2Authentication storedAuthentication = readAuthentication(accessToken.getValue());
            if ((storedAuthentication == null || !key.equals(authenticationKeyGenerator.extractKey(storedAuthentication)))) {
                // Keep the stores consistent (maybe the same user is
                // represented by this authentication but the details have
                // changed)
                storeAccessToken(accessToken, authentication);
            }

        }
        return accessToken;
    }

    /* ---------------------------------------------------------------------------
     * Part VI: Extension for Bybon business
     * ----------------------------------------------------------------------------
     */

    public void saveBackAccessToken(OAuth2AccessToken token){
        // token string - OAuth2AccessToken
        redisOperator.setObject(getKeyOfToken2TokenObj(token.getValue()), token, token.getExpiresIn());
    }
}
