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
package com.tdoer.security.oauth2.common.exception;

import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
/**
 * @author Htinker Hu (htinker@163.com)
 * @create 2017-09-19
 */
public class OAuth2TokenExpiredException extends OAuth2Exception {
    public OAuth2TokenExpiredException(String msg, Throwable t) {
        super(msg, t);
    }

    public OAuth2TokenExpiredException(String msg) {
        super(msg);
    }

    @Override
    public String getOAuth2ErrorCode() {
        return OAuth2ExceptionFactory.TOKEN_EXPIRED;
    }
}
