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
package com.tdoer.security.oauth2;
/**
 * @author Htinker Hu (htinker@163.com)
 * @create 2017-09-19
 */
public interface OAuth2Constants {
    // Redirect URI
    String REDIRECT_URI = "redirect_uri";

    String CLIENT_ID = "client-id";

    // Http Request/Response Header
    String AUTH_TOKEN = "auth-token";
    String USER_AGENT = "user-agent";
    String REMOTE_ADDRESS = "remote-address";
    String REMOTE_PORT = "remote-port";

    String CREATED_ON = "created-on";

    // Token kicked off
    String KICKED_OFF_BY = "kicked-off-by-token";
    String KICKED_OFF_ON = "kicked-off-on-date";
}
