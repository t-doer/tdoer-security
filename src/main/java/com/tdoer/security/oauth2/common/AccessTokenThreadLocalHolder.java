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
package com.tdoer.security.oauth2.common;

import org.springframework.security.oauth2.common.OAuth2AccessToken;
/**
 * @author Htinker Hu (htinker@163.com)
 * @create 2017-09-19
 */
public class AccessTokenThreadLocalHolder {
    protected static ThreadLocal<OAuth2AccessToken> tokenHolder = new ThreadLocal<>();

    protected static ThreadLocal<Boolean> markHolder = new ThreadLocal<>();

    public static OAuth2AccessToken getAccessToken(){
        return tokenHolder.get();
    }

    public static void setAccessToken(OAuth2AccessToken accessToken){
        tokenHolder.set(accessToken);
    }

    public static Boolean getRefreshedMark(){
        return markHolder.get();
    }

    public static void setRefreshedMark(Boolean mark){
        markHolder.set(mark);
    }
}
