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

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.Assert;
/**
 * @author Htinker Hu (htinker@163.com)
 * @create 2017-09-19
 */
public abstract class IgnoringPasswordEncoder implements PasswordEncoder {

    private static final String IGNORED_PASSOWRD = "b78e0e13f0ab83d2086870kl0caaacdaf1";

    private String ignoringPassword;

    public IgnoringPasswordEncoder(){
        this(IGNORED_PASSOWRD);
    }

    public IgnoringPasswordEncoder(String ignoringPassword) {
        Assert.notNull(ignoringPassword, "ignoringPassword cannot be null");
        this.ignoringPassword = ignoringPassword;
    }

    public String getIgnoringPassword() {
        return ignoringPassword;
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        if(ignoringPassword.equals(rawPassword.toString())){
            return true;
        }

        return doMatch(rawPassword, encodedPassword);
    }

    abstract protected boolean doMatch(CharSequence rawPassword, String encodedPassword);
}
