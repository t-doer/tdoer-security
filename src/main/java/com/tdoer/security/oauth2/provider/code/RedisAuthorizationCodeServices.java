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
package com.tdoer.security.oauth2.provider.code;

import com.tdoer.bedrock.Platform;
import com.tdoer.utils.cache.RedisJsonObjectOperator;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.code.RandomValueAuthorizationCodeServices;
/**
 * @author Htinker Hu (htinker@163.com)
 * @create 2017-09-19
 */
public class RedisAuthorizationCodeServices extends RandomValueAuthorizationCodeServices {

    private RedisJsonObjectOperator redisOperator;

    private static String KEY_PART = "auth:authorization_code:";

    public RedisAuthorizationCodeServices(RedisJsonObjectOperator redisTemplate) {
        this.redisOperator = redisTemplate;
    }

    private String getKeyOfAuthorizationCode2AuthObj(String code){
        return Platform.getCurrentEnvironment().getTenantId() + ":" + KEY_PART + code;
    }

    @Override
    protected void store(String code, OAuth2Authentication authentication) {
        // Keep the code in redis for 2 minutes, if the code is not consumed
        // in 2 minutes, it will be expired and removed by Redis.

        redisOperator.setObject(getKeyOfAuthorizationCode2AuthObj(code), authentication, 120);
    }

    @Override
    protected OAuth2Authentication remove(String code) {
        String key = getKeyOfAuthorizationCode2AuthObj(code);
        OAuth2Authentication ret = redisOperator.getObject(key, OAuth2Authentication.class);
        redisOperator.delete(key);
        return ret;
    }
}
