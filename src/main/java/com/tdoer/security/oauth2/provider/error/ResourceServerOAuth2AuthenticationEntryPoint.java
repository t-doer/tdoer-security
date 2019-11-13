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

import com.tdoer.springboot.rest.ResponseData;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.servlet.HandlerExceptionResolver;
import org.springframework.web.servlet.mvc.support.DefaultHandlerExceptionResolver;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
/**
 * @author Htinker Hu (htinker@163.com)
 * @create 2017-09-19
 */
public class ResourceServerOAuth2AuthenticationEntryPoint implements AuthenticationEntryPoint {
    /** Logger available to subclasses */
    protected final Log logger = LogFactory.getLog(getClass());

    private ResponseDataExceptionTranslator exceptionTranslator = new DefaultResponseDataExceptionTranslator();

    private ResponseDataRender dataRender = new DefaultResponseDataRender();

    // This is from Spring MVC.
    private HandlerExceptionResolver handlerExceptionResolver = new DefaultHandlerExceptionResolver();

    public void setExceptionTranslator(ResponseDataExceptionTranslator exceptionTranslator) {
        this.exceptionTranslator = exceptionTranslator;
    }

    public void setResponseDataRenderer(ResponseDataRender exceptionRenderer) {
        this.dataRender = exceptionRenderer;
    }

    /**
     * Commences an authentication scheme.
     * <p>
     * <code>ExceptionTranslationFilter</code> will populate the <code>HttpSession</code>
     * attribute named
     * <code>AbstractAuthenticationProcessingFilter.SPRING_SECURITY_SAVED_REQUEST_KEY</code>
     * with the requested target URL before calling this method.
     * <p>
     * Implementations should modify the headers on the <code>ServletResponse</code> as
     * necessary to commence the authentication process.
     *
     * @param request       that resulted in an <code>AuthenticationException</code>
     * @param response      so that the user agent can begin authentication
     * @param authException that caused the invocation
     */
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException{
        doHandle(request, response, authException);
    }

    protected final void doHandle(HttpServletRequest request, HttpServletResponse response, Exception authException)
            throws IOException, ServletException {
        try {
            ResponseData result = exceptionTranslator.translate(authException);

            dataRender.render(result, new ServletWebRequest(request, response));
            response.flushBuffer();
        }
        catch (ServletException e) {
            // Re-use some of the default Spring dispatcher behaviour - the exception came from the filter chain and
            // not from an MVC handler so it won't be caught by the dispatcher (even if there is one)
            if (handlerExceptionResolver.resolveException(request, response, this, e) == null) {
                throw e;
            }
        }
        catch (IOException e) {
            throw e;
        }
        catch (RuntimeException e) {
            throw e;
        }
        catch (Exception e) {
            // Wrap other Exceptions. These are not expected to happen
            throw new RuntimeException(e);
        }
    }
}
