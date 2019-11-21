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

import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.http.HttpServletRequest;

/**
 * @author Htinker Hu (htinker@163.com)
 * @create 2019-11-14
 */
public class AuthenticationEntryPointRequestMatcher implements RequestMatcher {

    protected MediaTypeRequestMatcher mediaTypeRequestMatcher;

    protected AntPathRequestMatcher urlRequestMatcher;

    public AuthenticationEntryPointRequestMatcher(String loginPath){
        urlRequestMatcher = new AntPathRequestMatcher(loginPath);
    }

    @Override
    public boolean matches(HttpServletRequest httpServletRequest) {
        if(urlRequestMatcher.matches(httpServletRequest)){
            if(mediaTypeRequestMatcher != null && mediaTypeRequestMatcher.matches(httpServletRequest)){
                return true;
            }
        }
        return false;
    }

    public void setMediaTypeRequestMatcher(MediaTypeRequestMatcher mediaTypeRequestMatcher){
        this.mediaTypeRequestMatcher = mediaTypeRequestMatcher;
    }
}
