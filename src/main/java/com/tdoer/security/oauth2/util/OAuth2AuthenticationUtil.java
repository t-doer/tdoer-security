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
package com.tdoer.security.oauth2.util;

import com.tdoer.security.oauth2.OAuth2Constants;
import com.tdoer.security.oauth2.common.exception.OAuth2AccessBlockedException;
import com.tdoer.security.oauth2.provider.authentication.CloudOAuth2AuthenticationDetails;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

import java.util.Map;
/**
 * @author Htinker Hu (htinker@163.com)
 * @create 2017-09-19
 */
public class OAuth2AuthenticationUtil {

    public static void collectBlockInfoFromAuthenctication(OAuth2Authentication auth, OAuth2AccessBlockedException ex){
        // TODO collect verification information: Client Id (`<tenantId>:<clientId>`), User Agent, Remote Address, Remote Port
        // ex.addAdditionalInformation(OAuth2Constants.CLIENT_ID, auth.getOAuth2Request().getClientId());
    }

    public static String getClientId(OAuth2Authentication authentication) {
        return authentication.getOAuth2Request().getClientId();
    }

    public static String getUserName(OAuth2Authentication authentication) {
        return authentication.getUserAuthentication() == null ? ""
                : authentication.getUserAuthentication().getName();
    }

    public static String getUserAgent(Authentication authentication) {
        String userAgent = null;

        Object details = authentication.getDetails();
        if(details != null){
            if(details instanceof Map){
                Map map = (Map) details;
                return (String)map.get(OAuth2Constants.USER_AGENT);
            }else{
                // must be CloudOAuth2AuthenticationDetails, otherwise please fix system error
                return ((CloudOAuth2AuthenticationDetails) details).getUserAgent();
            }
        }

        if(authentication instanceof  OAuth2Authentication){
            OAuth2Authentication auth = (OAuth2Authentication)authentication;
            return auth.getOAuth2Request().getRequestParameters().get(OAuth2Constants.USER_AGENT);
        }

        throw new InvalidTokenException("Unknown authentication details", null);
    }
}
