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
package com.tdoer.security.configure;

import com.tdoer.security.crypto.password.MD5PasswordEncoder;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

/**
 * @author Htinker Hu (htinker@163.com)
 * @create 2017-09-19
 */
@Configuration
@Order(-10)
public class ManagementConfiguration extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .requestMatchers().antMatchers("/management/**")
                .and()
                .authorizeRequests()
                .antMatchers("/management/info", "/management/health").permitAll()
                .anyRequest().hasRole("SYSTEM_OPERATOR")
                .and()
                .httpBasic()
                .and()
                .csrf().disable()
        ;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .passwordEncoder(new MD5PasswordEncoder())
                .withUser("tdoer")
                .password("fb3e9deaa6bffee9315c56acab2bd1e7") // md5 of operator@tdoer
                .roles("SYSTEM_OPERATOR");
    }
}