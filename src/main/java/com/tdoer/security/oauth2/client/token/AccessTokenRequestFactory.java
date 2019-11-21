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
package com.tdoer.security.oauth2.client.token;

import com.tdoer.bedrock.CloudEnvironment;
import com.tdoer.bedrock.Platform;
import com.tdoer.bedrock.PlatformConstants;
import com.tdoer.security.oauth2.OAuth2Constants;
import com.tdoer.springboot.util.NetworkUtil;
import com.tdoer.springboot.util.WebUtil;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.client.token.DefaultAccessTokenRequest;
import org.springframework.util.LinkedMultiValueMap;

import javax.servlet.http.HttpServletRequest;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.Map;
/**
 * @author Htinker Hu (htinker@163.com)
 * @create 2017-09-19
 */
public class AccessTokenRequestFactory {
    private AccessTokenRequestFactory(){}

    public static AccessTokenRequest create(HttpServletRequest request){

        DefaultAccessTokenRequest req = new DefaultAccessTokenRequest(request.getParameterMap());
        req.setCurrentUri((String) request.getAttribute("currentUri"));
        req.setAuthorizationCode(request.getParameter("code"));
        req.setStateKey(request.getParameter("state"));

        // Transfer user agent, remote address, remote port in AccessTokenRequest's parameters to AuthorizationServer
        Map<String, String> params = new LinkedHashMap<String, String>();

        String userAgent = WebUtil.findValueFromRequest(request, OAuth2Constants.USER_AGENT);
        if(userAgent != null){
            params.put(OAuth2Constants.USER_AGENT, userAgent);
        }
        params.put(OAuth2Constants.REMOTE_ADDRESS, NetworkUtil.getRemoteAddr(request));
        params.put(OAuth2Constants.REMOTE_PORT, "" + request.getRemotePort());
        req.setAll(params);

        // Transfer HttpServletRequest's headers in AccessTokenRequest's headers to AuthorizationServer
        LinkedMultiValueMap map = new LinkedMultiValueMap<String, String>();
        Enumeration<String> names = request.getHeaderNames();
        String headerName = null, headerValue = null;
        while(names.hasMoreElements()){
            headerName = names.nextElement();
            headerValue = request.getHeader(headerName);
            if(headerName != null && headerValue != null ){
                map.add(headerName, headerValue);
            }
        }

        // Transfer CloudEnvironment digest in AccessTokenRequest's headers to AuthorizationServer
        CloudEnvironment env = Platform.getCurrentEnvironment();
        map.add(PlatformConstants.ENVIRONMENT_DIGEST, env.getDigest().toDigestString());

        req.setHeaders(map);

        return req;
    }
}
