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

import com.tdoer.security.oauth2.OAuth2Constants;
import org.apache.commons.codec.Charsets;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.web.util.UriUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
/**
 * @author Htinker Hu (htinker@163.com)
 * @create 2017-09-19
 */
public class RedirectUriAuthenticationEntryPoint extends LoginUrlAuthenticationEntryPoint {

    private String targetUrlParameter = OAuth2Constants.REDIRECT_URI;

    /**
     * @param loginFormUrl URL where the login page can be found. Should either be
     *                     relative to the web-app context path (include a leading {@code /}) or an absolute
     *                     URL.
     */
    public RedirectUriAuthenticationEntryPoint(String loginFormUrl) {
        super(loginFormUrl);
    }

    public void setTargetUrlParameter(String targetUrlParameter) {
        this.targetUrlParameter = targetUrlParameter;
    }

    /**
     * Allows subclasses to modify the login form URL that should be applicable for a
     * given request.
     *
     * @param request   the request
     * @param response  the response
     * @param exception the exception
     * @return the URL (cannot be null or empty; defaults to {@link #getLoginFormUrl()})
     */
    @Override
    protected String determineUrlToUseForThisRequest(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) {
        String loginFormUrl = getLoginFormUrl();
        String redirectUri = UrlUtils.buildRequestUrl(request);
        // encode it
        String encodedRedirectUri = UriUtils.encode(redirectUri, Charsets.UTF_8);
        StringBuilder sb = new StringBuilder(loginFormUrl);
        if(!loginFormUrl.contains("?")){
            sb.append("?");
        }else if(!loginFormUrl.endsWith("&")){
            sb.append("&");
        }

        sb.append(targetUrlParameter).append("=").append(encodedRedirectUri);

        return sb.toString();
    }
}
