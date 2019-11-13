/*
 * Copyright 2006-2011 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */


package com.tdoer.security.oauth2.provider.authentication;

import com.tdoer.bedrock.CloudEnvironment;
import com.tdoer.bedrock.Platform;
import com.tdoer.bedrock.security.CloudAuthenticationDetails;
import com.tdoer.security.oauth2.OAuth2Constants;
import com.tdoer.springboot.util.NetworkUtil;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

/**
 * Copy from and modify {@link org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails},
 * by adding remote port, user agent and appId attributes, and enhancing the method to get request's
 * remote IP address which may be through proxies. -- Likai Hu, 2018/0/13.
 * <br>
 *------------------------------------------------------------------------------------------------------
 * <br>
 *
 * A holder of selected HTTP details related to an OAuth2 authentication request.
 * 
 * @author Dave Syer
 * 
 */
public class CloudOAuth2AuthenticationDetails implements CloudAuthenticationDetails {
	
	private static final long serialVersionUID = -4809832298438307309L;

	public static final String ACCESS_TOKEN_VALUE = org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails.class.getSimpleName() + ".ACCESS_TOKEN_VALUE";

	public static final String ACCESS_TOKEN_TYPE = org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails.class.getSimpleName() + ".ACCESS_TOKEN_TYPE";

    private final String tokenValue;

    private final String tokenType;

    private final String sessionId;

    private final String remoteAddress;

    private final int remotePort;

    private final String userAgent;

    private final Long tenantId;

    private final String clientId;

    private final String display;

    private Object decodedDetails;


	/**
	 * Records the access token value and remote address and will also set the session Id if a session already exists
	 * (it won't create one).
	 * 
	 * @param request that the authentication request was received from
	 */
	public CloudOAuth2AuthenticationDetails(HttpServletRequest request) {
		this.tokenValue = (String) request.getAttribute(ACCESS_TOKEN_VALUE);
		this.tokenType = (String) request.getAttribute(ACCESS_TOKEN_TYPE);
        HttpSession session = request.getSession(false);
        this.sessionId = (session != null) ? session.getId() : null;
		this.remoteAddress = NetworkUtil.getRemoteAddr(request);
		this.remotePort = request.getRemotePort();
		this.userAgent = request.getHeader(OAuth2Constants.USER_AGENT);

        CloudEnvironment env = Platform.getCurrentEnvironment();
        this.tenantId = env.getTenantId();
        this.clientId = env.getTenantClient().getGuid();

		StringBuilder builder = new StringBuilder();
		builder.append("tenantId=").append(tenantId);
		builder.append(", clientId=").append(clientId);
		if (remoteAddress!=null) {
			builder.append(", remoteAddress=").append(remoteAddress);
		}

		builder.append(", remotePort=").append(remotePort);
		if(userAgent != null){
		    builder.append(", userAgent=").append(userAgent);
        }
		if (sessionId!=null) {
			builder.append(", sessionId=<SESSION>");
		}
		if (tokenType!=null) {
			builder.append(", tokenType=").append(this.tokenType);
		}
		if (tokenValue!=null) {
			builder.append(", tokenValue=<TOKEN>");
		}

		this.display = builder.toString();
	}

	/**
	 * The access token value used to authenticate the request (normally in an authorization header).
	 * 
	 * @return the tokenValue used to authenticate the request
	 */
	public String getTokenValue() {
		return tokenValue;
	}
	
	/**
	 * The access token type used to authenticate the request (normally in an authorization header).
	 * 
	 * @return the tokenType used to authenticate the request if known
	 */
	public String getTokenType() {
		return tokenType;
	}

	/**
	 * Indicates the TCP/IP address the authentication request was received from.
	 * 
	 * @return the address
	 */
	public String getRemoteAddress() {
		return remoteAddress;
	}

	/**
	 * Indicates the <code>HttpSession</code> id the authentication request was received from.
	 * 
	 * @return the session ID
	 */
	public String getSessionId() {
		return sessionId;
	}

	/**
	 * The authentication details obtained by decoding the access token
	 * if available.
	 * 
	 * @return the decodedDetails if available (default null)
	 */
	public Object getDecodedDetails() {
		return decodedDetails;
	}

	/**
	 * The authentication details obtained by decoding the access token
	 * if available.
	 * 
	 * @param decodedDetails the decodedDetails to set
	 */
	public void setDecodedDetails(Object decodedDetails) {
		this.decodedDetails = decodedDetails;
	}

	public int getRemotePort() {
		return remotePort;
	}

	public String getUserAgent() {
		return userAgent;
	}

    public Long getTenantId() {
        return tenantId;
    }

    public String getClientId() {
        return clientId;
    }

    @Override
	public String toString() {
		return display;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((sessionId == null) ? 0 : sessionId.hashCode());
		result = prime * result + ((tokenType == null) ? 0 : tokenType.hashCode());
		result = prime * result + ((tokenValue == null) ? 0 : tokenValue.hashCode());
        result = prime * result + ((clientId == null) ? 0 : clientId.hashCode());
        result = prime * result + ((userAgent == null) ? 0 : userAgent.hashCode());
        result = prime * result + ((tenantId == null) ? 0 : tenantId.hashCode());
        result = prime * result + ((remoteAddress == null) ? 0 : remoteAddress.hashCode());
        result = prime * result + remotePort;

		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;

		CloudOAuth2AuthenticationDetails other = (CloudOAuth2AuthenticationDetails) obj;
        if (!this.toString().equals(other.toString())) {
            return false;
        }

        if(sessionId == null) {
            if(other.getSessionId() != null){
                return false;
            }
        }else if(!sessionId.equals(other.getSessionId())){
            return false;
        }

        if(tokenValue == null) {
            if(other.getTokenValue() != null){
                return false;
            }
        }else if(!tokenValue.equals(other.getTokenValue())){
            return false;
        }

		return true;
	}
	
	

}
