# T-Doer Security

T-Doer Security is to secure T-Doer Bedrock services based on OAuth 2.0.

To enable T-Doer Security, T-Doer Bedrock Services (Gateway, Authorization, Business and Infrastructure),
must implement and declare a bean of `com.tdoer.security.oauth2.provider.token.ResourceServerRefreshTokenServices`
which is used to read stored `org.springframework.security.oauth2.provider.OAuth2Authentication`,
`org.springframework.security.oauth2.common.OAuth2AccessToken`, and `org.springframework.security.oauth2.common.OAuth2RefreshToken` 
from access token string.
 
## 1. Gateway Service
 
### 1.1 Filters

Seq | Filter | Comment
---|---|---
1 | org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter | It will catch **UserRedirectRequiredException** which is thrown by **AccessTokenProvider** in **OAuth2ClientAuthenticationProcessingFilter** and send redirect response.
2 | com.tdoer.bedrock.web.CloudEnvironmentProcessingFilter | The filter will intercept all requests, parse out CloudEnvironment and set it into com.tdoer.bedrock.CloudEnvironmentHolder
3 | com.tdoer.bedrock.web.CloudServiceCheckAccessFilter | The filter will intercept all requests, Check access of client/application/service's request to a service. 403 response status will be returned if the request is not permitted
4 | com.tdoer.security.oauth2.client.filter.AccessTokenAuthenticationProcessingFilter |  The filter will intercept requests except for "login" and extract access token from request header, and load an authentication object into the SecurityContext
5 | com.tdoer.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter |  The filter will only intercept "login" request. An OAuth2 client filter that can be used to acquire an OAuth2 access token from an authorization server, and load an authentication object into the SecurityContext. 

### 1.2 Configurations

#### 1.2.1 EnableGatewayService

```

```

#### 1.2.2 Beans

- com.tdoer.security.oauth2.provider.token.ResourceServerRefreshTokenServices, needed by
 OAuth2ClientAuthenticationProcessingFilter, AccessTokenAuthenticationProcessingFilter

#### 1.2.3 application.yml

```
security:
  oauth2:
    # configure service to communicate with authorization service
    client:
      # retrieve token from authorization server by authorization code, user password etc.
      accessTokenUri: http://tdoer-auth/oauth/token
      # revoke token, DELETE http method
      revokeTokenUri: http://tdoer-auth/oauth/users/{user}/tokens/{token}
      # redirect to and ask user to authorize the client
      userAuthorizationUri: http://auth2dev.bybon.cn/oauth/authorize
      # clientId/client secret
      clientAuthenticationScheme: header
      # token
      authenticationScheme: header
      # redirect to and tell authorization server to logout, ie., revoke token
      authorizationServerLogoutUri: http://auth2dev.bybon.cn/logout
      # current service's login path
      loginPath: /login
      # current service's logout path
      logoutPath: /logout

```


## 2. Business Service
 
### 2.1 Filters

Seq | Filter | Comment
---|---|---
2 | com.tdoer.bedrock.web.CloudEnvironmentProcessingFilter | The filter will intercept all requests, parse out CloudEnvironment and set it into com.tdoer.bedrock.CloudEnvironmentHolder
3 | com.tdoer.bedrock.web.CloudServiceCheckAccessFilter | The filter will intercept all requests, Check access of client/application/service's request to a service. 403 response status will be returned if the request is not permitted
4 | com.tdoer.security.oauth2.client.filter.AccessTokenAuthenticationProcessingFilter |  The filter will intercept requests except for "login" and extract access token from request header, and load an authentication object into the SecurityContext

### 2.2 Configurations

#### 2.2.1 EnableBusinessService

```

```

#### 2.2.2 Beans

- org.springframework.security.oauth2.provider.token.ResourceServerRefreshTokenServices, needed by AccessTokenAuthenticationProcessingFilter

#### 2.2.3 application.yml

Noop

## Infrastructure Service & its Filters

Seq | Filter | Comment
---|---|---
2 | com.tdoer.bedrock.web.CloudEnvironmentProcessingFilter | The filter will intercept all requests, parse out CloudEnvironment and set it into com.tdoer.bedrock.CloudEnvironmentHolder
3 | com.tdoer.bedrock.web.CloudServiceCheckAccessFilter | The filter will intercept all requests, Check access of client/application/service's request to a service. 403 response status will be returned if the request is not permitted
4 | com.tdoer.security.oauth2.client.filter.AccessTokenAuthenticationProcessingFilter | The filter will intercept requests except for "login" and extract access token from request header, and load an authentication object into the SecurityContext

## Authorization Service & its Filters

#### OAuth2 AuthorizationServer

Seq | Filter | Comment
---|---|---
2 | com.tdoer.bedrock.web.CloudEnvironmentProcessingFilter | The filter will intercept all requests, parse out CloudEnvironment and set it into com.tdoer.bedrock.CloudEnvironmentHolder
3 | com.tdoer.bedrock.web.CloudServiceCheckAccessFilter | The filter will intercept all requests, Check access of client/application/service's request to a service. 403 response status will be returned if the request is not permitted
4 | org.springframework.security.web.authentication.www.BasicAuthenticationFilter |  The filter will intercept 'token' requests, authenticate client Id/secret and load an authentication object into the SecurityContext

#### Other

Seq | Filter | Comment
---|---|---
2 | com.tdoer.bedrock.web.CloudEnvironmentProcessingFilter | The filter will intercept all requests, parse out CloudEnvironment and set it into com.tdoer.bedrock.CloudEnvironmentHolder
3 | com.tdoer.bedrock.web.CloudServiceCheckAccessFilter | The filter will intercept all requests, Check access of client/application/service's request to a service. 403 response status will be returned if the request is not permitted
4 | com.tdoer.security.oauth2.client.filter.AccessTokenAuthenticationProcessingFilter | The filter will intercept requests except for "login" and extract access token from request header, and load an authentication object into the SecurityContext
 
## OAuth2 Configuration

The project customizes [Spring Security OAuth2](https://github.com/spring-projects/spring-security-oauth) 
based on [T-Doer Bedrock SaaS Framework](https://github.com/t-doer/tdoer-bedrock).

OAuth 2.0 is the industry-standard protocol for authorization, is an Authorization Framework, which enables 
 third-party application to obtain limited access to an HTTP service, either on behalf of a resource owner 
 by orchestrating an approval interaction between the resource owner and the HTTP service, or by allowing 
 the third-party application to obtain access on its own behalf.
 
The project will make T-Doer Bedrock SaaS Framework to integrate OAuth 2.0 Authorization Framework. Below
table shows the corresponding concepts between the 2 framework.

OAuth 2.0 | T-Doer Bedrock
---|---
Resource owner | User
Client | TenantClient
Client Id | TenantClient's GUID
Client Secret | TenantClient's Secret
Token config  | Client's ClientConfig's TokenConfig
Resource Server | Service
Authorization Server | Service (say, T-Doer Auth)

Grant types which are supported by Bedrock Service.

OAuth 2.0 Grant Type | Supported by T-Doer Bedrock Service
---|---
Authorization Code | Yes
Password | Yes
Implicit | No
Client Credental | No

## AuthenticationManager

OAuth2 Role | Needed By | AuthenticationToken | Comment
---|---|---|---
AuthorizationServer | RedisTokenServices | PreAuthenticatedAuthenticationToken | To check user authentication is still valid
AuthorizationServer | ResourceOwnerPasswordTokenGranter | UsernamePasswordAuthenticationToken | To check username/password
ResourceServer | OAuth2AuthenticationProcessingFilter | PreAuthenticatedAuthenticationToken | Transform an OAuth2 token into OAuth2Authentication
Client | OAuth2ClientAuthenticationProcessingFilter | | Consume authorization code into OAuth2Authentication

## Bedrock Service and Filters

#### Gateway and its filters


```
// Filter Chain - Authorization Server's protected endpoints, request must bring basic authorization information of
 client Id / client secret.
// BasicAuthenticationFilter will have a AuthenticationManager with ClientDetailsUserDetailsService.
OrRequestMatcher [requestMatchers=[
   Ant [pattern='/oauth/token'], 
   Ant [pattern='/oauth/token_key'], 
   Ant [pattern='/oauth/check_token']]
],[
   org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter@210635fd, 
   org.springframework.security.web.context.SecurityContextPersistenceFilter@52856ff9, 
   org.springframework.security.web.header.HeaderWriterFilter@312f3050,
   org.springframework.security.web.authentication.logout.LogoutFilter@3cdfbbef, 
   org.springframework.security.web.authentication.www.BasicAuthenticationFilter@11180750, 
   org.springframework.security.web.savedrequest.RequestCacheAwareFilter@5aa7cfdf, 
   org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter@123ca460,
   org.springframework.security.web.authentication.AnonymousAuthenticationFilter@63814bbe, 
   org.springframework.security.web.session.SessionManagementFilter@615bad16, 
   org.springframework.security.web.access.ExceptionTranslationFilter@23321be7, 
   org.springframework.security.web.access.intercept.FilterSecurityInterceptor@13dd7887
]

// Filter Chain - Resource Server's protected resources, requests must bring access token to access, 
//and resource can be protected by OAuth2 client roles, scopes and user roles etc.
OrRequestMatcher [requestMatchers=[
   Ant [pattern='/oauth/users/**'], 
   Ant [pattern='/oauth/clients/**'], 
   Ant [pattern='/me']]
], [
   org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter@ac417a2,
   org.springframework.security.web.context.SecurityContextPersistenceFilter@342a1f84, 
   org.springframework.security.web.header.HeaderWriterFilter@7f4f1536, 
   org.springframework.security.web.authentication.logout.LogoutFilter@67ceeffd,
   org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationProcessingFilter@21a5b599,
   org.springframework.security.web.savedrequest.RequestCacheAwareFilter@77d0dbba, 
   org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter@70b196d3,
   org.springframework.security.web.authentication.AnonymousAuthenticationFilter@64c95480, 
   org.springframework.security.web.session.SessionManagementFilter@1ad1b737, 
   org.springframework.security.web.access.ExceptionTranslationFilter@58636b50, 
   org.springframework.security.web.access.intercept.FilterSecurityInterceptor@69069866
]

// Filter Chain - Any others, protected by spring security, local user login and user roles
org.springframework.security.web.util.matcher.AnyRequestMatcher@1
, [
   org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter@1c43df76,
   org.springframework.security.web.context.SecurityContextPersistenceFilter@7b79ff1c, 
   com.bybon.springboot.oauth2.client.filter.OAuth2AccessTokenProcessingFilter@788efe,
   org.springframework.security.web.header.HeaderWriterFilter@246de37e, 
   org.springframework.security.web.authentication.logout.LogoutFilter@2335aef2, 
   org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter@2f9addd4, 
   org.springframework.security.web.savedrequest.RequestCacheAwareFilter@527d48db, 
   org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter@194037f9,
   org.springframework.security.web.authentication.AnonymousAuthenticationFilter@ff2266c, 
   org.springframework.security.web.session.SessionManagementFilter@19647566, 
   org.springframework.security.web.access.ExceptionTranslationFilter@2e40fdbd, 
   org.springframework.security.web.access.intercept.FilterSecurityInterceptor@39a8e2fa
]

 ```

## 1. Customization Guide

- Customized Configurations
- Minimize OAuth2 core implementations' customization

  - Remove ResourceOwnerPasswordTokenTemplate
  - Remove RemoteResourceRestTemplate

## 2. Customization for SaaS

`@EnableCloudEnvironment` for Client, AuthorizationServer, ResourceServer, and add CloudEnvironmentParseFilter before SecurityContextPersistenceFilter.

### 2.1 Client-side Customization

User OAuth2RestTemplate to achieve access token and request resources posted by ResourceServer.

Each request, new OAuth2ProtectedResourceDetails, DefaultOAuth2ClientContext, and OAuth2RestTemplate.

1. Parse out CloudEnvironment from HTTP request

   - com.tdoer.cloudfw.impl.configuration.EnableCloudEnvironment | Need to enable cloud environment for Client
   - org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter | Configure HttpSecurity and add CloudEnvironmentParseFilter before SecurityContextPersistenceFilter.

2. SaaS: Client's Identifier, credentials and scope do not read from static configurations, instead, from
 CloudEnvironment's TenantClient object, and Auth2ProtectedResourceDetails's `clientId` is CloudEnvironment's
  `TenantClient's GUID`

   - com.tdoer.security.oauth2.client.CloudOAuth2ClientProperties
   - com.tdoer.security.oauth2.client.CloudResourceDetailsFactory
   - com.tdoer.security.oauth2.config.annotation.web.configuration.OAuth2PropertiesConfiguration
   - com.tdoer.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client
   
3. SaaS: Token Request `/oauth/token` from Client to AuthorizationServer for a new or refreshed access token. A token request from client must contains a valid client identifier and credentials.
  
   - com.tdoer.security.oauth2.client.CloudOAuth2TokenTemplate
   - com.tdoer.security.oauth2.client.token.grant.client.ClientCredentialsTokenTemplate
   - com.tdoer.security.oauth2.client.token.grant.code.AuthorizationCodeTokenTemplate
   - com.tdoer.security.oauth2.client.token.grant.implicit.ImplicitTokenTemplate
   - com.tdoer.security.oauth2.client.token.grant.password.ResourceOwnerPasswordTokenTemplate


4. SaaS: transfer http request's headers, user agent, remote address, ports and cloud environment digest in AccessTokenRequest by AccessTokenProvider to AuthorizationServer

   - com.tdoer.security.oauth2.client.token.AccessTokenRequestFactory
   - com.tdoer.security.oauth2.config.annotation.web.configuration.OAuth2ClientConfiguration
   
5. SaaS: Resource requests from Client to ResourceServer. Resources protected by ResourceServer. Request must bring a valid access token.
     
   - com.tdoer.security.oauth2.client.CloudResourceRestTemplate

6. SaaS: Transfer cloud environment digest, token, and user information if exists, in resource request's header by CloudResourceRestTemplate to ResourceServer

  - com.tdoer.security.oauth2.client.CloudOAuth2RequestAuthenticator
  - com.tdoer.security.oauth2.client.CloudResourceRestTemplate

7. SaaS: SSO

  - Need to get TenantClient of "passport" for the request tenant, when redirect user's login request to token server.
  
  - com.tdoer.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter
  - com.tdoer.security.oauth2.config.annotation.web.configurers.SsoSecurityConfigurer
  - com.tdoer.security.oauth2.config.annotation.web.configuration.OAuth2SsoConfiguration
  - com.tdoer.security.oauth2.config.annotation.web.configuration.EnableOAuth2Sso
  
6. New Feature: Support Ribbon RestTemplate for token request, so that can find AuthorizationServer by named service through Eureka.

  - com.tdoer.security.oauth2.client.token.grant.client.CloudClientCredentialsTokenProvider
  - com.tdoer.security.oauth2.client.token.grant.code.CloudAuthorizationCodeTokenProvider
  - com.tdoer.security.oauth2.client.token.grant.implicit.CloudImplicitTokenProvider
  - com.tdoer.security.oauth2.client.token.grant.password.CloudUserPasswordTokenProvider
  
7. New Feature: Richer OAuth2Exception (See also corresponding AuthorizationServer Customization's 'Richer OAuth2Exception')

  - com.tdoer.security.oauth2.common.exception.*
  - com.tdoer.security.oauth2.http.converter.DelegatingFormOAuth2ExceptionHttpMessageConverter  

8. New Feature: Sessionless Web Application

   - com.tdoer.security.oauth2.config.annotation.web.configuration.OAuth2ClientConfiguration
   - com.tdoer.security.oauth2.client.token.DefaultOAuth2ClientContext | request-scope bean
   - com.tdoer.security.oauth2.common.AccessTokenThreadLocalHolder

```
Examples
```

### 2.2 AuthorizationServer Customization

1. Parse out CloudEnvironment from cloud environment digest in token request's header

  - com.tdoer.cloudfw.impl.configuration.EnableCloudEnvironment | Need to enable cloud environment for AuthorizationServer
  - com.tdoer.security.oauth2.config.annotation.web.configuration.AuthorizationServerSecurityConfiguration | Add CloudEnvironmentParseFilter before SecurityContextPersistenceFilter.
  - com.tdoer.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer

2. Read ClientDetails from CloudEnvironment's Client.

   - com.tdoer.security.oauth2.provider.CloudClientDetails | Created from CloudEnvironment's Client
   - com.tdoer.security.oauth2.provider.CloudClientDetailsService | Parse `<tenantId>:<clientId>` and load CloudClientDetails
   - com.tdoer.security.oauth2.config.annotation.configuration.ClientDetailsServiceConfiguration
   
3. New Feature: Richer OAuth2Exception (See also corresponding Client-side Customization's 'Richer OAuth2Exception')

  - com.tdoer.security.oauth2.common.exception.*
  - com.tdoer.security.oauth2.provider.password.ResourceOwnerPasswordTokenGranter 
  
5. New Feature: Token Creation Policy: allow all, kick off previous login session, block new coming

  - TokenCreationPolicy / RedisTokenService
  - com.tdoer.security.oauth2.provider.authentication.AccessBlockedException
  - com.tdoer.security.oauth2.common.exception.AccessKickedOffException
  
6. New Feature: ClientCategory-based PasswordEncoder
 
  - com.tdoer.cloudfw.security.PasswordEncoderRegistry
  - com.tdoer.cloudfw.security.CloudPasswordEncoder    
     
### 2.3 ResourceServer Customization

1. Parse out CloudEnvironment from cloud environment digest in resource request's header

  - com.tdoer.cloudfw.impl.configuration.EnableCloudEnvironment | Need to enable cloud environment for ResourceServer
  - com.tdoer.security.oauth2.config.annotation.web.configuration.ResourceServerConfiguration | Add CloudEnvironmentParseFilter before SecurityContextPersistenceFilter.
  - com.tdoer.security.oauth2.config.annotation.web.configuration.EnableResourceServer
  
2. Parse out user from user information, or token if user information is for found, in resource request's header

   
  
## Customization for the Features




- RequestTokenExtractor, export auth token from request header or cookie




- [TODO] Unknown app id exception
- [TODO] KickedOffException process and test
- [TODO] OAuth2ExceptionFactory, block and kicked off exception

- Client-based user data source (clientId ==> tag ==> user service)
- Web SSO, separate B-end user and C-end user
- AccessTokenProvider and TokenEndpoint should pass over app-id and user-agent, pass them in AccessTokenRequest and pass into TokenRequest
- Refresh token when token is expired
- Check token request validity: token, appId, user-agent in resource server by AbstractTokenAuthenticationManager
- AppID-based user role loading, adjust history application's user services
- [TODO] Redis's string persistence
- Cluster supporing, both tdoer-auth and clients, either share distributed session in redis or remove session using token
- [TODO] UserDetailsService and clientDetailsService performance, one request one sql query 


## Token Requests

  There are 3 token requests from Client to AuthorizationServer:
  
    - `/oauth/token` - Request AuthorizationServer to grant an access token for the client in person of resource owner
    - `/oauth/token_key` - Read JWT key's value from AuthorizationServer
    - `oauth/check_token` - Request AuthorizationServer to check if an access token is still valid
    
  A token request from client must contains a valid client identifier and credentials.
  
    - com.tdoer.security.oauth2.client.token.grant.client.ClientCredentialsTokenTemplate
    - com.tdoer.security.oauth2.client.token.grant.code.AuthorizationCodeTokenTemplate
    - com.tdoer.security.oauth2.client.token.grant.implicit.ImplicitTokenTemplate
    - com.tdoer.security.oauth2.client.token.grant.password.ResourceOwnerPasswordTokenTemplate
    
    
  Examples:
  
  ```
     
  ```
  
## Resource Request

  Resource requests from Client to ResourceServer. Resources protected by ResourceServer. Request must bring a valid access token.
  
  - com.tdoer.security.oauth2.client.CloudResourceRestTemplate
  
## Example #1: Retrive an access token from AuthorizationServer with "password" grant type
  
  ```
  
  
 
  ```
  
- OAuth2RestTemplate => RemoteResourceRestTemplate

  Request header must contain cloud environment digest and auth token
  
  see CloudOAuth2RequestAuthenticator
  
## Authentication

**Use com.tdoer.security.oauth2.provider.authentication.CloudOAuth2AuthenticationDetailsSource, so 
com.tdoer.security.oauth2.provider.authentication.CloudOAuth2AuthenticationDetails.**

- Web: User/Password form login authentication, Token Web Server authenticates user login

  - AnthenticationDetails: com.tdoer.cloudfw.security.WebAuthenticationDetails
  - AuthenticationDetailsSource: com.tdoer.cloudfw.security.WebAuthenticationDetailsSource  | Used in HTTP Form Login (account / password)
  - Authentication: org.springframework.security.authentication.UsernamePasswordAuthenticationToken
  - Authenticated Authentication: org.springframework.security.authentication.UsernamePasswordAuthenticationToken
  - AuthenticationManager: org.springframework.security.authentication.dao.DaoAuthenticationProvider: UserDetailsService | PasswordEncoder
  - Filter: org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter
  - Configurer: HttpSecurity#formLogin() = org.springframework.security.config.annotation.web.configurers.FormLoginConfigurer
  
- Client: SSO authorization code authentication, Client-side user login request

  - AnthenticationDetails: com.tdoer.security.oauth2.provider.authentication.CloudOAuth2AuthenticationDetails
  - AuthenticationDetailsSource: com.tdoer.security.oauth2.provider.authentication.CloudOAuth2AuthenticationDetailsSource
  - Authentication: org.springframework.security.oauth2.provider.OAuth2Authentication
  - Authenticated Authentication: org.springframework.security.oauth2.provider.OAuth2Authentication
  - AuthenticationManager: Noop
  - Filter: com.tdoer.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter
  - Configurer: com.tdoer.security.oauth2.config.annotation.web.configurers.SsoSecurityConfigurer

- ResourceServer: Token authentication by ResourceServer which is not with AuthorizationServer

  - AnthenticationDetails: org.springframework.security.authentication.AuthenticationDetailsSource
  - AuthenticationDetailsSource: org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetailsSource
  - Authentication: org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken | org.springframework.security.oauth2.provider.authentication.BearerTokenExtractor
  - Authenticated Authentication: org.springframework.security.oauth2.provider.OAuth2Authentication
  - AuthenticationManager: org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationManager | org.springframework.security.oauth2.provider.token.ResourceServerTokenServices
  - Filter: org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationProcessingFilter
  - Configurer: com.tdoer.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer

- ResourceServer: Token authentication by ResourceServer which is with AuthorizationServer, different token service

  - AnthenticationDetails: org.springframework.security.authentication.AuthenticationDetailsSource
  - AuthenticationDetailsSource: org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetailsSource
  - Authentication: org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken | org.springframework.security.oauth2.provider.authentication.BearerTokenExtractor
  - Authenticated Authentication: org.springframework.security.oauth2.provider.OAuth2Authentication
  - AuthenticationManager: org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationManager | org.springframework.security.oauth2.provider.token.ResourceServerTokenServices (diff)
  - Filter: org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationProcessingFilter
  - Configurer: com.tdoer.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer
  
- AuthorizationServer: Client/Secret authentication, AuthorizationServer authenticates token request

  - AnthenticationDetails: org.springframework.security.web.authentication.WebAuthenticationDetails
  - AuthenticationDetailsSource: org.springframework.security.web.authentication.WebAuthenticationDetailsSource
  - Authentication: org.springframework.security.authentication.UsernamePasswordAuthenticationToken
  - Authenticated Authentication: org.springframework.security.authentication.UsernamePasswordAuthenticationToken
  - AuthenticationManager: org.springframework.security.authentication.dao.DaoAuthenticationProvider: org.springframework.security.oauth2.provider.ClientDetailsService | PasswordEncoder
  - Filter: org.springframework.security.oauth2.provider.client.ClientCredentialsTokenEndpointFilter
  - Configurer: com.tdoer.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer
  
- AuthorizationServer: ResourceOwnerPasswordTokenGranter

  - AnthenticationDetails: a map of request parameters
  - AuthenticationDetailsSource: No
  - Authentication: org.springframework.security.authentication.UsernamePasswordAuthenticationToken
  - Authenticated Authentication: org.springframework.security.oauth2.provider.OAuth2Authentication
  - AuthenticationManager: Need one
  - TokenGranter: org.springframework.security.oauth2.provider.password.ResourceOwnerPasswordTokenGranter
  - Configurer: com.tdoer.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer
    
- AuthorizationServer: AuthorizationCodeTokenGranter

- AuthorizationServer: RedisTokenServices refresh token

    
## Customized OAuth2Exceptions

#### Case #1: "token" or  "check token" request

1. Client sends "token" or "check token" request to AuthorizationServer's TokenEndpoint, by its AccessTokenProvider's RestTemplate;
2. AuthorizationServer somehow generates any exceptions, and TokenEndpoint's ExceptionHandler will intercept and translate the exceptions into ResponseEntity<OAuth2Exception> by org.springframework.security.oauth2.provider.error.WebResponseExceptionTranslator.
3. Client receives the response and build OAuth2Exception by OAuth2Exception#valueOf() in FormOAuth2ExceptionHttpMessageConverter in AccessTokenProvider's RestTemplate;

#### Case #2: "authorize" request

1. Client sends authorization request to AuthorizationServer's AuthorizationEndpoint;
2. If AuthorizationEndpoint fails to process the authorization request, it will redirect the request back, by appending the query parameters:

   - error
   - error_description
   - OAuth2Exception's additional information

3. Client receives and processes the redirect request, and if the request contains error information, CloudAccessTokenProviderChain will build and throw OAuth2Exception by OAuth2Exception#valueOf().   

#### Case #3: other request, for example, login etc.

1. Any web request to authorization server;
2. AuthorizationServer somehow generates any exceptions, and will be caught by ExceptionHandler, it will intercept and translate the exceptions into ResponseEntity<OAuth2Exception> by org.springframework.security.oauth2.provider.error.WebResponseExceptionTranslator.
3. ResponseEntity<OAuth2Exception> will be rendered by OAuth2ExceptionRenderer, to Client or Browser;





##### How to verify access token? Client Id (`<tenantId>:<clientId>`), User Agent, Remote Address, Remote Port?

- Client: AccessTokenProvider should pass the verification elements as request parameters, so need a customized AccessTokenRequestFactory (com.tdoer.security.oauth2.client.token.AccessTokenRequestFactory).
- AuthorizationServer: TokenGranter should collect the verification elements, so need a customized OAuth2RequestFactory
- AuthorizationServer: Need a customized AuthenticationKeyGenerator, to generate authentication key.

4. New Feature: Token Valiation: client Id (`<tenantId>:<clientId>`), user agent, http request's remote address, remote port
  
  - com.tdoer.cloudfw.security.CloudAuthenticationDetails
  - com.tdoer.security.oauth2.provider.authentication.CloudOAuth2AuthenticationDetails
  - com.tdoer.security.oauth2.provider.authentication.OAuth2AuthenticationDetailsSource | Userd in Access Token process filter
  - com.tdoer.cloudfw.security.WebAuthenticationDetails
  - com.tdoer.cloudfw.security.WebAuthenticationDetailsSource  | Used in HTTP Form Login (account / password)
  
  
  - DefaultAuthenticationKeyGenerator
  - RedisTokenStore / RedisTokenService
  
## Todo

- Verify access token: Client Id (`<tenantId>:<clientId>`), User Agent, Remote Address, Remote Port
- Collect Block Info: OAuth2AuthenticationUtil#collectBlockInfo()
- Check Kicked-off access token in Filter

## Usage

### SSO

Main points:

  - EnableOAuth2Sso on WebSecurityConfigurerAdapter
  - Declare bean of "org.springframework.security.oauth2.provider.token.ResourceServerTokenServices"
  - Configuration   
    - security.oauth2.client.*
    - security.oauth2.resource.*

Example:

```

```    
```
security:
  oauth2:
    client:
      accessTokenUri: http://tdoer-auth/oauth/token
      revokeTokenUri: http://tdoer-auth/oauth/users/{user}/tokens/{token}
      userAuthorizationUri: http://auth2dev.bybon.cn/oauth/authorize
      # clientId/client secret
      clientAuthenticationScheme: header
      # token
      authenticationScheme: header
      authorizationServerLogoutUri: http://auth2dev.bybon.cn/logout
      loginPath: /login
    resource:
      userInfoUri: http://tdoer-auth/me
      preferTokenInfo: false
```    