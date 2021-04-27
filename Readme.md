# Spring Security
 
## 목차 
[1. 스프링 시큐리티 의존성 추가](#스프링-시큐리티-의존성이-추가되면-생기는-일) <br/>
[2. WebSecurityConfigurerAdapter](#WebSecurityConfigurerAdapter) <br/>
[3. HttpSecurity](#HttpSecurity) <br/>
[4. http.formLogin()](#http.formLogin) <br/>
[5. UsernamePasswordAuthenticationFilter](#UsernamePasswordAuthenticationFilter) <br/> 
[6. FilterChainProxy](#FilterChainProxy) <br/>
[7. Logout](#Logout) <br/>
[8. LogoutFilter](#LogoutFilter) <br/>
[9. RememberMe](#RememberMe) <br/> 
[10. RememberMeAuthenticationFilter](#RememberMeAuthenticationFilter) <br/> 
***
 
## 스프링 시큐리티 의존성이 추가되면 생기는 일 

서버가 가동되면 스프링 시큐리티의 초기화 작업 및 보안설정이 이뤄진다.  

별도의 설정이나 구현없이 기본적인 시큐리티 설정이 적용된다. 특징은 다음과 같다. 
  - 모든 요청은 인증이 되야 한다.
  - 인증방식은 formLogin 방식과 httpBasic 로그인 방식이 제공된다. 
  - 기본 로그인 페이지가 제공된다. 
  - 기본 계정도 한 개 제공된다. 

기본적인 제공도 있지만 여러가지 계정과 권한이 필요로 하고 어떤 페이지에는 아무나 접근할 수도 있다. 그리고 DB 사용도 필요하다. 

*** 

## WebSecurityConfigurerAdapter

스프링 시큐리티 웹 보안 기능 초기화 및 설정을 해주는 클래스

스프링 시큐리티 의존성을 넣으면 초기화를 하고 설정을 하는 기능을 여기서 한다. 

  - WebSecurityConfigurerAdapter 클래스의 getHttp() 메소드에서 applyDefaultConfiguration() 메소드와 configure() 메소드를 통해 기본 설정을 한다. 기본 설정은 다음과 같다. 

    - ```java
      // applyDefaultConfiguration 메소드 
      http.csrf()
      http.addFilter(new WebAsyncManagerIntegrationFilter());
      http.exceptionHandling();
      http.headers();
      http.sessionManagement();
      http.securityContext();
      http.requestCache();
      http.anonymous();
      http.servletApi();
      http.apply(new DefaultLoginPageConfigurer());
      http.logout();
      ```

    - ```java
      // configure 메소드
      http.authorizeRequests((requests) -> {
                  ((AuthorizedUrl)requests.anyRequest()).authenticated();
              });
      http.formLogin();
      http.httpBasic();
      ```
이 클래스는 HttpSecurity 클래스를 생성하고 여기서 세부적인 보안기능을 설정할 수 있는 API를 제공해준다. 

보안정책을 커스텀하게 사용하기 위해선 새로운 클래스를 만들고 WebSecurityConfigurerAdapter를 상속받아야 한다. 이를 통해 configure() 라는 메소드 오버라이딩을 통해 기본적으로 제공하는 보안설정을 사용자 정의할 수 있다.  이 메소드에서 HttpSecurity 에 접근할 수 있고 여기에 있는 API를 통해 인증/인가 설정을하면 된다. 그리고 @EnableWebSecurity 붙여야 한다. 

  - @EnableWebSecurity란? 
    - 이 에노테이션은 WebSecurityConfiguration.class, SpringWebMvcImportSelector.class, OAuth2ImportSelector.class, HttpSecurityConfiguration.class 들을 import 해서 실행시켜주는 역할을 한다. 
    - @EnableWebSecurity 에노테이션이 붙어야 스프링에서 Global한 WebSecurity에 적용시킬 수 있다. 


***


## HttpSecurity

세부적인 보안 기능을 제공해준다. 예를들면 인증에 관련된 API와 인가에 관련된 API를 제공해준다. 
- 인증 API
  - http.formLogin()
  - http.logOut()
  - http.csrf()
  - http.httpBasic()
  - http.SessionManagement()
  - http.RememberMe()
  - http.ExceptionHandling()
  - http.addFilter()

- 인가 API
  - http.authorizeRequests()
  - http.antMatcher(/admin)
  - http.hasRole(USER)
  - http.permitAll()
  - http.authenticated()
  - http.fullyAuthentication()
  - http.access(hasRole(USER))
  - http.denyAll()

***

## http.formLogin

http.formLogin() 메소드를 통해 Form 로그인 인증 기능이 작동한다.

formLogin()과 관련해서 하위 API들을 살펴보면 다음과 같다. 
  - http.formLogin().loginPage("/login.html") 을 통해서 사용자 정의 로그인 페이지를 설정할 수 있다. 
  - http.formLogin().defaultSuccessUrl("/home")을 통해서 로그인 성공 후 페이지를 등록할 수 있다.
  - http.formLogin().failureUrl("/")을 통해서 로그인 실패 후 이동 페이지를 등록할 수 있다. 
  - http.formLogin().usernameParameter("username")를 통해서 기본 form에서 등록하는 아이디 이름을 변경할 수 있다.
  - http.formLogin().passwordParameter("password")를 통해서 기본 form에서 등록하는 패스워드 이름을 변경할 수 있다. 
  - http.formLogin()loginProcessingUrl("/login")을 통해서 로그인 form action을 받는 url을 등록할 수 있다.
  - http.formLogin().successHandler(loginSuccessHandler())를 통해서 로그인 성공 후 실행할 핸들러를 등록할 수 있다. 
  - http.formLogin().failureHandler(loginFailureHandler())를 통해서 로그인 실패 후 실행할 핸들러를 등록할 수 있다. 


***

## UsernamePasswordAuthenticationFilter

http.formLogin() 처리를 하는 Filter

- 이 필터가 어떻게 처리하는지 알아보자. 
  1. AntPathRequestMatcher(/login)에서 먼저 사용자가 로그안할려는 요청 URL을 보고 로그인 경로가 맞는지 확인한다. 만약 이 경로가 맞다면 처리 진행를 시작하고 맞지 않다면 다음 필터로 넘긴다. 
  
  2. 사용자 요청에 들어간 Username과 Password를 통해서 Authentication 객체를 만든다. 이 Authentication 객체를 통해서 실제 인증처리를 한다. 
  
  3. AuthenticationManager가 이 Authentication 객체를 바탕으로 인증처리를 한다. AuthenticationManager는 AuthenticationProvider에게 인증 처리를 위임하게 된다. AuthenticationProvider가 인증에 성공했는지 여부를 리턴한다. 
        - 인증에 실패하게 되면 AuthenticationException을 던지게 되고 UsernamePasswordAuthenticationFilter가 이 작업을 처리하게 된다. FailureHandler와 같은 작업도 이후에 처리하게 된다. 
        - 인증에 성공하게 된다면 권한정보와 사용자 정보를 통해 함께 Authentication 객체를 만들고 AuthenticationManager에게 돌려준다. 
  
  4. AuthenticationManager는 이 객체를 다시 Filter에게 돌려주고 Filter는 SecurityContext에 저장하게 된다. 여기에 인증 객체가 저장되게 된다. 저장 후 SuccessHandler() 메소드를 호출하게 된다 SecurityContext는 나중에 session에도 저장이 된다. 이후에 참조할 수 있도록. 


***

## FilterChainProxy

Filter들을 관리해주는 빈이다. additionalFilters를 보면 14개정도의 Filter가 들어가있다. 인증/인가 처리를 할 때 이 Filter들을 하나하나씩 해보면서 처리를 한다. 

http.formLogin()을 설정하면 UsernamePasswordAuthenticationFilter가 처리하게 된다. 


***

## Logout 

로그아웃 한다는 의미는 세션을 무효화하고 인증 토큰을 삭제해야하며(Security Context), 쿠키를 지워야 한다. 그리고 Redirect Page로 이동시켜야 한다. 

로그아웃 API는 http.logout()이다. 

하위 API들을 살펴보면 다음과 같다.
  - http.logout.logoutUrl("/logout")을 통해서 로그아웃 처리 URL을 설정할 수 있다. 
  - http.logout.logoutSuccessUrl("/login")을 통해서 로그아웃 성공 URL을 설정할 수 있다. 
  - http.logout.deleteCookies("JSESSIONID", "remember-me")을 통해서 발급된 쿠키들을 삭제할 수 있다. 
  - http.logout.addLogoutHandler(logoutHandler())을 통해서 스프링 시큐리티의 기본적인 로그아웃 핸들러에다가 커스텀한 로그아웃 핸들러를 추가할 수 있다. 
  - http.logout.logoutSuccessHandler(logoutSucessHandler())을 통해서 로그아웃 후 실행할 핸들러를 등록시킬 수 있다. 


***

## LogoutFilter

기본적으로는 POST 요청을 통해서 받는다. 

처리과정은 다음과 같다.
  
  1. 먼저 AntPathRequestMatcher(/logout)에서 로그아웃 요청 경로가 맞는지 확인한다. 아니라면 다음 필터로 넘기고 매치가 되면 Authentication 객체를 Security Context에서 꺼내온다. 그 후 Authentication 객체를 SecurityContextLogoutHandler에게 전달해준다. 
  
  2. SecurityContextLogoutHandler는 Authentication 객체안에 있는 세션 Id를 통해서 세션을 무효화하고 쿠키를 삭제하고 Security Context를 삭제하고 Authentication 객체를 null로 바꾼다. 이는 Spring Security가 제공해주는 logoutHandler들과 사용자가 정의한 logoutHandler를 통해 처리된다. (http.logout.addLogoutHandler()를 통해 추가된 핸들러들) 
  
  3. 성공적으로 로그아웃 된다면 SimpleLogoutSuccessHandler()를 호출한다. 

***

## RememberMe

Spring Security에서 Remember Me 기능을 로그인할 때 킬 수 있다. 이 기능은 세션이 만료되고 어플리케이션이 종료되도 어플리케이션이 사용자를 기억하는 기능으로 사용자의 쿠키를 통해 기억한다. 

Remeber Me 기능을 적용한다면 로그인하면 서버는 사용자에게 토큰을 주고 사용자는 쿠키에 저장한다. 

로그아웃하면 이 RememberMe 쿠키를 지워야 한다. 

RememberMe는 http.rememberMe() 를 통해 가능하다. 

하위 API를 살펴보면 다음과 같다. 
  - http.rememberMe().rememberMeParameter("remember")를 통해서 사용자가 로그인 할 때 기본 피라미터 명은 remember-me 이다.
  - http.rememberMe().tokenValiditySeconds(3600)을 통해서 rememberMe 토큰의 유효기간을 등록할 수 있다. 기본적으로는 14일이다. 
    - http.rememberMe().alwaysRemember(true)를 통해서 rememberMe 기능을 항상 활성화 시킬 수 있다. 
  - http.rememberMe().userDetailsService(userDeatilsService)를 통해서 rememberMe 기능을 수행할 때 사용자 계정을 조회하는 서비스이다. 

스프링 시큐리티가 어떻게 인증된 사용자인지 아는지는 사용자의 요청에 JSESSIONID이 담기게 되고 Spring Security는 이 ID를 통해서 세션에서 Security Context를 가지고 올 수 있고 여기에 Authentication 객체가 담기게 된다. 그러므로 사용자가 JSESSIONID를 지우게 된다면 다시 로그인 해야한다. 

하지만 RememberMe 토큰을 가지고 있게 된다면 서버에서 이 정보를 바탕으로 디코딩하고 파싱해서 유저 정보를 만들고  인증 객체를 만들어서 다시 세션을 만들어준다. 

***

## RememberMeAuthenticationFilter

이 Filter가 동작하는 조건은 Authentication 객체가 null일 경우이다. 즉 Security Context에 Authentication 객체가 없다면 동작한다는 의미다. 

또 다른 조건은 RememberMe Cookie가 있어야 작동한다. 이게 없다면 다음 FilterChain으로 넘어가게 된다. 

필터의 동작은 RememberMeService 인터페이스 구현체에 따라서 동작하는데 크게 두가지가 있다.
  - TokenBasedRememberMeServices
    - 기본적으로 14일동안 동작한다. 
  - PersistentTokenBasedRememberMeServices
    - Database에 있는 Token과 비교를 한다.

Cookie에 토큰이 있더라도 정상적인 규격에 맞는 토큰인지 확인을 한다. 

그 후 사용자의 토큰과 서버에 저장된 토큰이 일치하는지 비교한다. 이후에 이 User 정보를 바탕으로 DB에 User 계정이 존재하는지 확인하고 맞다면 Authentication 객체를 만들게 된다. 그 다음 AuthenticationManager에게 전달해줘서 마무리한다. 

AbstractAuthenticationProcessingFilter.successfulAuthentication() 메소드에 있는 rememberMe.loginSuccess() 메소드를 통해서 사용자에게 전달하는 응답객체에 remember-me 쿠키를 만들어서 전달해주는 걸 볼 수 있다. 이 정보에 Authentication Username과 Password를 가지고 만든다. 



