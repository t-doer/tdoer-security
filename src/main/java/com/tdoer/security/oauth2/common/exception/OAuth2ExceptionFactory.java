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

import java.util.Map;
import java.util.Set;

/**
 * The factory supports extended OAuth2Exceptions by the framework
 *
 * @author Htinker Hu (htinker@163.com)
 * @create 2017-09-19
 */
public class OAuth2ExceptionFactory {

    // Extended OAuth2Exception
    public static final String ACCOUNT_DISABLED = "account_disabled";
    public static final String ACCOUNT_EXPIRED = "account_expired";
    public static final String ACCOUNT_LOCKED = "account_locked";
    public static final String CREDENTIAL_EXPIRED = "credential_expired";
    public static final String TOKEN_EXPIRED = "token_expired";
    public static final String TOKEN_REVOKED = "token_revoked";
    public static final String ACCESS_KICKED_OFF = "access_kicked_off";
    public static final String ACCESS_BLOCKED = "access_blocked";

    /**
     * Create a OAuth2Exception from the input error information. It supports the exceptions
     * extended in the framework from Spring OAuth2.
     *
     * @param errorParams A map of error informations
     * @return OAuth2Exception
     * @see {@link OAuth2Exception#valueOf(Map)}
     */
    public static OAuth2Exception newOAuth2Exception(Map<String, String> errorParams){
        String errorCode = errorParams.get(OAuth2Exception.ERROR);
        String errorMessage = errorParams.containsKey(OAuth2Exception.DESCRIPTION) ? errorParams.get(OAuth2Exception.DESCRIPTION)
                : null;
        OAuth2Exception ex = create(errorCode, errorMessage);
        Set<Map.Entry<String, String>> entries = errorParams.entrySet();
        for (Map.Entry<String, String> entry : entries) {
            String key = entry.getKey();
            if (!OAuth2Exception.ERROR.equals(key) && !OAuth2Exception.DESCRIPTION.equals(key)) {
                ex.addAdditionalInformation(key, entry.getValue());
            }
        }

        return ex;
    }

    public static OAuth2Exception create(String errorCode, String errorMessage){
        if (ACCOUNT_DISABLED.equals(errorCode)) {
            return new OAuth2AccountDisabledException(errorMessage);
        }
        else if (ACCOUNT_EXPIRED.equals(errorCode)) {
            return new OAuth2AccountExpiredException(errorMessage);
        }
        else if (ACCOUNT_LOCKED.equals(errorCode)) {
            return new OAuth2AccountLockedException(errorMessage);
        }
        else if (CREDENTIAL_EXPIRED.equals(errorCode)) {
            return new OAuth2CredentialExpiredException(errorMessage);
        }
        else if (TOKEN_EXPIRED.equals(errorCode)) {
            return new OAuth2TokenExpiredException(errorMessage);
        }
        else if (ACCESS_KICKED_OFF.equals(errorCode)) {
            return new OAuth2AccessKickedOffException(errorMessage);
        }
        else if (TOKEN_REVOKED.equals(errorCode)) {
            return new OAuth2TokenRevokedException(errorMessage);
        }else if (ACCESS_BLOCKED.equals(errorCode)) {
            return new OAuth2AccessBlockedException(errorMessage);
        }else{
            // Spring OAuth2Exception
            return OAuth2Exception.create(errorCode,errorMessage);
        }
    }
}
