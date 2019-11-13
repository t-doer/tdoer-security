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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
/**
 * @author Htinker Hu (htinker@163.com)
 * @create 2017-09-19
 */
public class RedirectUriAuthenticationFailureHandler implements AuthenticationFailureHandler {

    private Logger logger = LoggerFactory.getLogger(this.getClass());

    private String targetUrlParameter = OAuth2Constants.REDIRECT_URI;

    private String defaultFailureUrl;

    private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    public RedirectUriAuthenticationFailureHandler(String defaultFailureUrl) {

        Assert.hasText(defaultFailureUrl, "defaultFailureUrl cannot be blank");
        this.defaultFailureUrl = defaultFailureUrl;
    }

    public void setTargetUrlParameter(String targetUrlParameter) {
        this.targetUrlParameter = targetUrlParameter;
    }

    public void setRedirectStrategy(RedirectStrategy redirectStrategy) {
        this.redirectStrategy = redirectStrategy;
    }

    /**
     * Called when an authentication attempt fails.
     *
     * @param request   the request during which the authentication attempt occurred.
     * @param response  the response.
     * @param exception the exception which was thrown to reject the authentication
     */
    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        String redirectUri = getRedirectURI(request);
        StringBuilder sb = new StringBuilder(defaultFailureUrl);
        if(StringUtils.hasText(redirectUri)){
            if(!defaultFailureUrl.contains("?")){
                sb.append("?");
            }else if(!defaultFailureUrl.endsWith("&")){
                sb.append("&");
            }

            sb.append(targetUrlParameter).append("=").append(redirectUri);
        }

        String url = sb.toString();
        logger.debug("Redirecting to " + url);
        redirectStrategy.sendRedirect(request, response, url);
    }

    private String getRedirectURI(HttpServletRequest request){
        String redirectUri = request.getParameter(targetUrlParameter);
        if(!StringUtils.hasText(redirectUri)){
            redirectUri = WebUtil.getRequestParameterFromReferer(request, targetUrlParameter);
        }

        return redirectUri;
    }
}
