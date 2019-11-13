package com.tdoer.security.oauth2.config.annotation.web.configuration;

import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

import java.lang.annotation.*;

/**
 * Enable OAuth2 Single Sign On (SSO). If there is an existing
 * {@link WebSecurityConfigurerAdapter} provided by the user and annotated with
 * {@code @EnableOAuth2Sso}, it is enhanced by adding an authentication filter and an
 * authentication entry point. If the user only has {@code @EnableOAuth2Sso} but not on a
 * WebSecurityConfigurerAdapter then one is added with all paths secured.
 *
 * @author Dave Syer
 * @since 1.3.0
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@EnableOAuth2Client
@Import({OAuth2SsoConfiguration.class})
public @interface EnableOAuth2Sso {

}
