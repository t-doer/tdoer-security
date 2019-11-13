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
package com.tdoer.security.oauth2.provider.authentication;

import com.tdoer.security.oauth2.OAuth2Constants;
import com.tdoer.springboot.util.WebUtil;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.authentication.BearerTokenExtractor;

import javax.servlet.http.HttpServletRequest;
/**
 * @author Htinker Hu (htinker@163.com)
 * @create 2017-09-19
 */
public class RequestTokenExtractor extends BearerTokenExtractor {

    @Override
    protected String extractToken(HttpServletRequest request) {

        String token = WebUtil.findValueFromRequest(request, OAuth2Constants.AUTH_TOKEN);
        if (token == null) {
            token = super.extractToken(request);
        }

        return token;
    }

    @Override
    public Authentication extract(HttpServletRequest request) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if(authentication != null){
            return authentication;
        }

        return super.extract(request);
    }
}
