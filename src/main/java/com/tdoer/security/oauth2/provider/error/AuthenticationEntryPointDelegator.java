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
package com.tdoer.security.oauth2.provider.error;

import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.web.accept.HeaderContentNegotiationStrategy;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;
/**
 * @author Htinker Hu (htinker@163.com)
 * @create 2017-09-19
 */
public class AuthenticationEntryPointDelegator implements AuthenticationEntryPoint{

     private ResourceServerOAuth2AuthenticationEntryPoint resourceEntryPoint;
     private LoginUrlAuthenticationEntryPoint webEntryPoint;
     private MediaTypeRequestMatcher resourcePreferredMatcher;

     public AuthenticationEntryPointDelegator(String loginFormUrl ){
          this(new ResourceServerOAuth2AuthenticationEntryPoint(), new LoginUrlAuthenticationEntryPoint(loginFormUrl));
     }

    public AuthenticationEntryPointDelegator(ResourceServerOAuth2AuthenticationEntryPoint resourceEntryPoint, LoginUrlAuthenticationEntryPoint webEntryPoint){
        this.resourceEntryPoint = resourceEntryPoint;
        this.webEntryPoint = webEntryPoint;

        resourcePreferredMatcher = new MediaTypeRequestMatcher(
                new HeaderContentNegotiationStrategy(), MediaType.APPLICATION_JSON,
                MediaType.APPLICATION_JSON_UTF8);
        resourcePreferredMatcher.setIgnoredMediaTypes(Collections.singleton(MediaType.ALL));
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        try {
             if (resourcePreferredMatcher.matches(request)){
                 resourceEntryPoint.commence(request, response, authException);
            }else{
                 webEntryPoint.commence(request, response, authException);
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
