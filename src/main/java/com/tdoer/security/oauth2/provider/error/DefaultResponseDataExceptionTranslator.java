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

import com.tdoer.security.oauth2.common.exception.*;
import com.tdoer.springboot.http.StatusCodes;
import com.tdoer.springboot.rest.ResponseData;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.*;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.common.DefaultThrowableAnalyzer;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.common.exceptions.UnauthorizedUserException;
import org.springframework.security.web.util.ThrowableAnalyzer;
import org.springframework.web.HttpRequestMethodNotSupportedException;
/**
 * @author Htinker Hu (htinker@163.com)
 * @create 2017-09-19
 */
public class DefaultResponseDataExceptionTranslator implements ResponseDataExceptionTranslator {

    private ThrowableAnalyzer throwableAnalyzer = new DefaultThrowableAnalyzer();

    public void setThrowableAnalyzer(ThrowableAnalyzer throwableAnalyzer) {
        this.throwableAnalyzer = throwableAnalyzer;
    }

    @Override
    public ResponseData translate(Throwable e) {
        // Try to extract a SpringSecurityException from the stacktrace
        Throwable[] causeChain = throwableAnalyzer.determineCauseChain(e);
        Exception ase = (OAuth2Exception) throwableAnalyzer.getFirstThrowableOfType(
                OAuth2Exception.class, causeChain);

        if (ase != null) {
            return translateOAuth2Exception((OAuth2Exception) ase);
        }

        ase = (AuthenticationException) throwableAnalyzer.getFirstThrowableOfType(AuthenticationException.class,
                causeChain);
        if (ase != null) {
            return translateAuthenticationException((AuthenticationException) ase);
        }

        ase = (AccessDeniedException) throwableAnalyzer
                .getFirstThrowableOfType(AccessDeniedException.class, causeChain);
        if (ase instanceof AccessDeniedException) {
            return ResponseData.status(StatusCodes.ACCESS_DENIED);
        }

        ase = (HttpRequestMethodNotSupportedException) throwableAnalyzer
                .getFirstThrowableOfType(HttpRequestMethodNotSupportedException.class, causeChain);
        if (ase instanceof HttpRequestMethodNotSupportedException) {
            return ResponseData.methodNotAllowed();
        }

        return ResponseData.internalServerError();
    }

    protected ResponseData translateOAuth2Exception(OAuth2Exception e){
        if(e instanceof OAuth2AccountExpiredException){
            return ResponseData.status(StatusCodes.USER_ACCOUNT_EXPIRED).data(e.getAdditionalInformation());
        }else if(e instanceof OAuth2CredentialExpiredException){
            return ResponseData.status(StatusCodes.USER_CREDENTIAL_EXPIRED).data(e.getAdditionalInformation());
        }else if(e instanceof OAuth2AccountDisabledException){
            return ResponseData.status(StatusCodes.USER_ACCOUNT_DISABLED).data(e.getAdditionalInformation());
        }else if(e instanceof OAuth2AccountLockedException){
            return ResponseData.status(StatusCodes.USER_ACCOUNT_LOCKED).data(e.getAdditionalInformation());
        }else if(e instanceof OAuth2TokenExpiredException) {
            return ResponseData.status(StatusCodes.ACCESS_TOKEN_EXPIRED).data(e.getAdditionalInformation());
        }else if(e instanceof OAuth2AccessKickedOffException) {
            return ResponseData.status(StatusCodes.ACCESS_TOKEN_REPLACED).data(e.getAdditionalInformation());
        }else if(e instanceof OAuth2TokenRevokedException) {
            return ResponseData.status(StatusCodes.ACCESS_TOKEN_REVOKED).data(e.getAdditionalInformation());
        }else if(e instanceof InvalidGrantException){
            return ResponseData.status(StatusCodes.INVALID_LOGIN_PASSWORD);
        }else if(e instanceof OAuth2AccessBlockedException){
            return ResponseData.status(StatusCodes.ACCESS_BLOCKED).data(e.getAdditionalInformation());
        }else if(e instanceof UnauthorizedUserException){
            return ResponseData.status(StatusCodes.UNAUTHORIZED).data(e.getAdditionalInformation());
        }else{
            return ResponseData.status(StatusCodes.ACCESS_DENIED).data(e.getAdditionalInformation());
        }
    }

    protected ResponseData translateAuthenticationException(AuthenticationException e){
        if(e instanceof AccountExpiredException){
            return ResponseData.status(StatusCodes.USER_ACCOUNT_EXPIRED);
        }else if(e instanceof CredentialsExpiredException){
            return ResponseData.status(StatusCodes.USER_CREDENTIAL_EXPIRED);
        }else if(e instanceof DisabledException){
            return ResponseData.status(StatusCodes.USER_ACCOUNT_DISABLED);
        }else if(e instanceof LockedException){
            return ResponseData.status(StatusCodes.USER_ACCOUNT_LOCKED);
        }else if(e instanceof InsufficientAuthenticationException){
            return ResponseData.status(StatusCodes.UNAUTHORIZED);
        }else {
            return ResponseData.status(StatusCodes.INVALID_LOGIN_PASSWORD);
        }
    }
}
