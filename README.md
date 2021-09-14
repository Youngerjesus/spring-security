# Spring Security
 
## 목차 

- [스프링 시큐리티 의존성 추가](#스프링-시큐리티-의존성이-추가되면-생기는-일)

- [WebSecurityConfigurerAdapter](#WebSecurityConfigurerAdapter)

- [HttpSecurity](#HttpSecurity)

- [http.formLogin()](#http-formLogin)

- [UsernamePasswordAuthenticationFilter](#UsernamePasswordAuthenticationFilter) 

- [FilterChainProxy](#FilterChainProxy)

- [Logout](#Logout)

- [LogoutFilter](#LogoutFilter)

- [RememberMe](#RememberMe) 

- [RememberMeAuthenticationFilter](#RememberMeAuthenticationFilter) 

- [AnonymousAuthenticationFilter](#AnonymousAuthenticationFilter) 

- [동시 세션 제어](#동시-세션-제어) 

- [세션 고정 보호](#세션-고정-보호)  

- [세션 정책](#세션-정책) 

- [SessionManagementFilter](#SessionManagementFilter) 

- [ConcurrentSessionFilter](#ConcurrentSessionFilter) 

- [권한설정과 표현식](#권한설정과-표현식) 

- [ExceptionTranslationFilter](#ExceptionTranslationFilter)

- [RequestCacheAwareFilter](#RequestCacheAwareFilter) 

- [CsrfFilter](#CsrfFilter) 

- [DelegatingFilterProxy](#DelegatingFilterProxy) 

- [필터 초기화와 다중 설정 클래스](#필터-초기화와-다중-설정-클래스)  

- [Authentication](#Authentication) 

- [SecurityContextHolder](#SecurityContextHolder)  

- [SecurityContextPersistenceFilter](#SecurityContextPersistenceFilter) 

- [Authentication Flow](#Authentication-Flow) 

- [AuthenticationManager](#AuthenticationManager) 

- [AuthenticationProvider](#AuthenticationProvider)

- [인가 개념 및 필터 이해:Authorization, FilterSecurityInterceptor](#인가-개념-및-필터-이해:Authorization,-FilterSecurityInterceptor)

- [인가 결정 심의자: AccessDeniedManager, AccessDecisionVoter](#인가-결정-심의자:-AccessDeniedManager,-AccessDecisionVoter)

***
 
## 스프링 시큐리티 의존성이 추가되면 생기는 일 

서버가 가동되면 스프링 시큐리티의 초기화 작업 및 보안설정이 이뤄진다.  

별도의 설정이나 구현없이 기본적인 시큐리티 설정이 적용된다. 특징은 다음과 같다. 
  - 모든 요청은 인증이 되야 한다.
  - 인증방식은 formLogin 방식과 httpBasic 로그인 방식이 제공된다. 
  - 기본 로그인 페이지가 제공된다. 
  - 기본 계정도 한 개 제공된다. 

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

## http formLogin

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

- RememberMe 토큰에는 기본적으로 ExpirationTime 과 Username, MD5 Hash 값이 들어있게 된다. 

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

***

## AnonymousAuthenticationFilter

익명 사용자 인증 필터로서 역할. 

Security Conext안에 Authentication 객체가 존재하는 경우에는 다음 필터로 넘기지만 Authentication 객체가 null 일 경우 AnonymousAuthenticationToken을 Security Context에 넣어주는 역할을 한다. 즉 익명 사용자라고 할지라도 토큰을 가지게 한다. 이를 통해 SSR에서 인증 여부를 구현할 때 isAnouymous() 메소드와 isAuthenticated() 로 구분해서 사용하는게 가능하다. 

AnonymousAuthenticationToken은 인증을 받은게 아니므로 세션에 저장하지는 않는다. 


코드로 보면 다음과 같다. 

```java
// AnonymousAuthenticationFilter 
@Override
	public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
			throws IOException, ServletException {
		if (SecurityContextHolder.getContext().getAuthentication() == null) {
			SecurityContextHolder.getContext().setAuthentication(createAuthentication((HttpServletRequest) req));
			if (this.logger.isTraceEnabled()) {
				this.logger.trace(LogMessage.of(() -> "Set SecurityContextHolder to "
						+ SecurityContextHolder.getContext().getAuthentication()));
			}
			else {
				this.logger.debug("Set SecurityContextHolder to anonymous SecurityContext");
			}
		}
		else {
			if (this.logger.isTraceEnabled()) {
				this.logger.trace(LogMessage.of(() -> "Did not set SecurityContextHolder since already authenticated "
						+ SecurityContextHolder.getContext().getAuthentication()));
			}
		}
		chain.doFilter(req, res);
	}

```
- 여기서 createAuthentication() 메소드를 보면 AnonymousAuthenticationToken을 만든다. 이 토큰을 바탕으로 Security Context에 넣어주는 역할을 AnonymousAuthenticationFilter가 한다. 


*** 

## 동시 세션 제어 

동일한 계정으로 인증을 받을 때 세션에 기록되는데 이 개수를 어떻게 제어하는지에 대한 전략이다.

전략은 크게 두개가 있다. 최대 세션 허용 개수가 1개라고 가정해보자.
    
  1. 이전 사용자 세션 만료
     - 이는 첫번째 사용자가 인증을하고 세션을 만들고 두번째 사용자가 인증을 하면 새로운 세션이 만들어지고 첫번째 사용자의 세션을 만료시킨다. 
  
  2. 현재 사용자 인증 실패 
     - 이는 첫번째 사용자가 인증을하고 세션을 만들고 두번째 사용자가 인증을 하면 인증 예외를 발생시킨다. 

동시 세션 제어는 http.sessionManagement() 메소드를 통해 가능하다. 

http.sessionManagement() 의 하위 API는 다음과 같다. 

  - http.sessionManagement.maximumSessions(1) 을 통해 최대 허용 가능한 세션의 수를 설정할 수 있다. -1 값으로 설정하면 무제한 로그인 세션이 허용된다. 
  - http.sessionManagement.maxSessionsPreventsLogin(true) 을 true 값을 통해 동시 로그인을 차단할 수 있다. false 로 설정하면 기존 세션이 만료되는 전략이다.
  - http.sessionManagement.invalidSessionUrl("/invalid") 을 통해 세션이 유효하지 않을 때 이동 할 페이지를 설정할 수 있다.
  - http.sessionManagement.expiredUrl("/expired") 설정을 통해 세션이 만료된 경우 이동 할 페이지를 설정할 수 있다. 

***

## 세션 고정 보호

세션 고정 공격을 보호하기 위해 인증에 성공할 때마다 새로운 JSESSIONID를 발급해주는 방법이다. 

이는 http.sessionManagement().sessionFixation().changeSessionId() 매소드를 통해 가능하다.
  - 기본 전략으로 사용자의 세션은 그대로 두고 세션 ID만 바꾸는 방법이다. 

또 다른 것으로는 http.sessionManagement.sessionFixation.migrateSession() 과 http.sessionManagement.sessionFixation.newSession() 이 있다
  - 새로운 세션 ID를 생성하는 것은 동일하다. changeSessionId()와 migratesSession() 차이는 서블릿 버전에 따라서 다르다는 차이만 있다. migrateSession()은 이전의 세션에서 설정한 여러가지 값들을 재사용하는 걸 말하고 newSession()은 새로운 세션을 만드는 걸 말한다.  

***

## 세션 정책 

세션 정책은 http.sessionManagement.sessionCreationPolicy(SessionCreationPolicy.If_Required) 메소드를 통해 가능하다.  
  - SessionCreationPolicy.Always 을 통해 스프링 시큐리티가 항상 세션을 생성하도록 설정할 수 있다. 
  - SessionCreationPolicy.If_Required 를 통해 스프링 시큐리티가 필요할 때 세션을 생성하도록 설정할 수 있다. 
  - SessionCreationPolicy.Never 을 통해 스프링 시큐리티가 생성하지 않지만 이미 존재하면 사용하도록 할 수 있다. 
  - SessionCreationPolicy.Stateless 을 통해 스프링 시큐리티가 생성하지 않고 존재해도 사용하지 않도록 할 수 있다. 예를 들면 JWT 토큰을 통해 사용할 때 이 정책을 사용하면 된다. 

***

## SessionManagementFilter

하는 일은 크게 4가지가 있다.
  - 세션 관리
    - 인증 시 사용자의 세션정보를 등록, 조회, 삭제등의 세션 관리를 한다. 
  - 동시적 세션 제어
    - 동일 계정으로 접속할 때 허용되는 최대 세션 수를 설정하거나 전략을 설정할 수 있다. 
  - 세션 고정 보호 
    - 인증할 때마다 새로운 세션 Id를 발급하도록 해서 공격자의 쿠키 조작을 방지할 수 있도록 한다. 
  - 세션 생성 정책 
    - 다양한 세션 정책을 지원한다. (e.g Always, If_Required, Never, Stateless)

***

## ConcurrentSessionFilter

매 요청 마다 현재 사용자의 세션 만료 여부를 체크한다. 만료되었을 경우 만료 처리를 하는데 로그아웃 처리를 하던가 오류페이지로 응답한다. 

ConcurrentSessionFilter는 SessionManagement와 연계해서 동시적 세션 제어를 한다. 

어떻게 연계하는지 살펴보자.
  1. 이전 사용자가 인증을 하고 세션에 등록했다고 가정해보자. 
  
  2. 동일한 새로운 사용자가 와서 인증을 하면 SessionManagementFilter가 처리를 한다. 이때 최대 허용 가능한 세션이 초과했을 경우 동시적 세션 제어 전략에 따라서 다르겠지만 기본 전략인 이전 사용자 세션 만료 전략에 따라서 즉시 이전 세션을 만료시킨다. (sesion.expireNow()) 
  
  3. 그 후에 이전 사용자가 요청을 하면 ConcurrentSessionFilter 에서 처리를 하는데 session.isExpired() 메소드를 통해 요청마다 세션이 만료되었는지 검사하고 만료되었다면 Logout 처리를 하던가 오류 페이지로 보낸다. 
  
  이 과정을 SessionMangementFilter 클래스와 ConcurrentSessionFilter 클래스에서 연계해서 살펴보면 다음과 같다. 
  
  1. 처음 사용자가 인증을 할려고 Username과 Password를 입력하면 UsernamePasswordAuthenticationFilter가 세션 정보를 넣어주려고 처리를 한다. 이때 ConcurrentSessionControlAuthenticationStrategy 클래스라는 동시 세션 제어를 관리해주는 클래스에 요청을 해서 현재 이 사용자가 가지고 있는 세션의 개수를 조회하고 그 개수가 최대 허용 가능한 세션 개수보다 작은지 검사한다. 
  
  2. 이를 통과하면 ChangedSessionIdAuthenticationStrategy 클래스에서 session.changeSessionId() 메소드를 통해 세션 Id를 바꿔주는 메소드를 호출한다. 
  
  3. 그 후 RegisterSessionAuthenticationStarategy 클래스에서 세션 정보를 등록하고 UsernamePasswordAuthenticationFilter는 성공적으로 처리를 완료한다. 여기서 CompositeSessionAuthenticationStrategy는 ConcurrentSessionControlAuthenticationStrategy 클래스와 ChangedSessionIdAuthenticationStrategy 클래스, RegisterSessionAuthenticationStarategy 클래스를 포함한다.  
  
  4. 두번째 사용자가 같은 계정을 가지고 요청할려고 하면 동일하게 UsernamePasswordAuthenticationFilter 를 거치게 되고 ConcurrentSessionControlAuthenticationStrategy 에서 최대 허용 가능한 세션을 초과했는지 검사하게 된다. 이때 초과됐다면 동시 세션 전략에 따라서 인증 실패 예외인 SessionAuthenticationException을 내던가 session.expireNow() 메소드를 통해 이전 세션을 무효화 시킨다. 그 다음 처리는 처음 사용자와 동일하다. 
  
  5. 처음 사용자가 세션이 만료되었고 어떤 요청을 보내게 되면 이때 ConcurrentSessionFilter가 매 요청마다 세션이 만료되었는지 검사한다. (session.isExpired()) 만료 되었다면 로그아웃 하고 이를 처리할 페이지로 옮긴다.  

***

## 권한설정과 표현식 

권한 설정은 선언적 방식과 동적 방식을 통해서 할 수 있다. 

- 선언적 방식

  - URL

    - http 객체를 통해서 가능하다 - http.anyMatcher("/users/**").hasRole("USER")

    - ```java
      @Override
      protected void configure(HttpSecurity http) throws Exception{
        
        http 
          		.antMatcher("/shop/**")
          		.authorizeRequest()
          			.antMatchers("/shop/login","/shop/users/**").permitAll() // (1)
          			.antMatchers("/shop/mypage").hasRole("USER") // (2)
          			.antMatchers("/shop/admin/pay").access("hasRole('ADMIN')"); 
        				.antMatchers("/shop/admin/**").access("hasRole('ADMIN') or hasRole('SYS')"); 
        				.anyRequest().authenticated(); 
      }
      ```

      - http.antMatcher() 를 통해서 보안이 적용할 경로를 설정할 수 있다. 이 부분을 생략하면 모든 부분에서 보안 검사를 실행하게 된다. 
      - (1) 에서는 /shop/login 으로 오는 요청이나 /shop/users/ 이후에 오는 모든 요청은 다 허용하겠다 라는 뜻이다. 
      - (2) 에서는 USER 권한을 가지고 있어야 접근이 가능하다 라는 뜻이다. 

    - 인가 API 표현식은 다음과 같다. 

      - authenticated() 를 통해 인증된 사용자의 접근을 허용할 수 있다.
      - fullyAuthenticated() 를 통해 인증된 사용자의 접근을 허용하지만 rememberMe 인증은 제외할 수 있다.
      - permitAll() 를 통해 어떤 사용자든 접근을 허용할 수 있다.
      - denyAll() 를 통해 어떤 사용자든 접근을 막을 수 있다.
      - anonymous() 를 통해 익명 사용자의 접근을 허용할 수 있다. (주의 USER 권한은 ANONYMOUS 권한의 상위 호환이 아니다. )
      - rememberMe() 를 통해 이걸 통해서 인증된 사용자의 접근을 허용할 수 있다. 
      - access() 를 통해 주어진 SpEL 표현식의 평가 결과가 true이면 접근을 허용할 수 있다. 
      - hasRole() 를 통해 주어진 사용자가 이 권한이 있다면 허용할 수 있다.
      - hasAuthority() 를 통해 사용자가 주어진 권한이 있다면 접근을 허용할 수 있다. 
      - hasAnyRole() 를 통해 사용자가 주어진 권한들 중  어떤 것이라도 있다면 접근을 허용할 수 있다.
      - hasAnyAuthority() 를 통해 사용자가 주어진 권한 중 어떤 것이라도 있다면 접근을 허용할 수 있다. 
      - hasIpAddress() 를 통해 주어진 Ip로부터 요청이 있다면 접근을 허용할 수 있다. 

  - Method

    - 메소드 위에 에노테이션을 통해서 가능하다. - @PreAuthorize("hasRole('USER')")

- 동적 방식 

  - URL 방식과 Method 방식이 있지만 이는 DB 연동을 통해서 한다. 

***

## ExceptionTranslationFilter 

이 필터는 크게 두가지 종류의 예외를 처리한다. AuthenticationException 과 AccessDeniedException 예외 이 예외들은 FilterChain의 가장 마지막에 있는 FilterSecurityInterceptor 가 발생시킨다. FilterSecurityInterceptor 앞에 있는 Filter가 바로 ExceptionTranslationFilter 이다. ExceptionTranslationFilter 가 다음 필터를 호출할 때 FilterSecurityInterceptor 를 try-catch로 감싸고 있고 이를 통해 FilterSecurityInterceptor 가 던진 예외를 처리한다. 

AuthenticationException
  - 스프링이 제공하는 AuthenticationEntryPoint 인터페이스 구현체를 호출한다. 이를 통해 로그인 페이지로 이동하던가 401 권한 없음 오류 코드를 전달할 수 있다. AuthenticationEntryPoint 인터페이스를 사용자가 정의한 구현체를 쓸 수도 있다. 

  - 인증 예외가 발생하기 전의 요청 정보를 저장할 수 있다. 이게 무슨 뜻이냐면 권한이 있는 리소스에 접근을 하고자 하는데  인증이 안되있다면 AuthenticationEntryPoint 의 처리에 따라서 로그인 페이지로 이동하게 된다. 이때 이전에 요청했던 정보를 캐싱하고 있다가 인증을 하고나서 다시 재요청을 하도록 한다. RequestCache 클래스를 통해 세션에 저장된 사용자의 이전 요청 정보를 꺼내오는 방법을 쓸 수 있다. 이때 꺼내오는 객체가 SavedRequest 클래스 타입인데   여기에는 사용자가 요청했던 request 파라미터 값들과 그 당시의 헤더값들이 저장된다.  

AccessDeniedException
  - 권한이 없을때 발생하는 예외로 AccessDeniedHandler 에서 예외를 처리하도록 할 수 있다. 

처리 플로우는 다음과 같다. 
  1. 인증을 하지 않는 사용자가 권한이 있어야 접근할 수 있는 리소스에 요청을 했다. 이때 FilterSecurityInterceptor가 인가 예외를 던진다. 인증 예외가 아닌 이유는 익명 사용자의 경우에도 AuthenticationToken이 생기기 떄문이다. 
  
  2. 이를 통해 ExceptionTranslationFilter가 AccessDeniedException 예외를 처리하는데 익명 사용자의 요청이나 RememberMe 인증인 경우에는 AccessDeniedHandler 를 호출하는게 아니라 인증 예외 처리에서 실행하는 흐름대로 처리한다.
  
  3. 그러므로 AuthenticationEntryPoint 에서 response.redirect('/login') 으로 페이지를 이동시키고 요청 정보를 세션에 저장한다 이때 DefaultSavedReqeust 객체로 저장된다. 세션에 저장하도록 하는 역할은 HttpSessionRequestCache 가 한다. 


http.exceptionHandling() 메소드를 통해 예외처리 기능이 작동하도록 할 수 있다. 
  - http.exceptionHandling.authenticationEntryPoint(authenticationEntryPoint()) 메소드를 통해 인증 실패시 처리할 핸들러를 등록할 수 있다.
  
  - http.exceptionHandling.accessDeniedHandler(accessDeniedHandler()) 메소드를 통해 인가 실패시 처리할 핸들러를 등록할 수 있다.  

***

## RequestCacheAwareFilter 

RequestCacheAwareFilter 는 세션에 SavedRequest가 저장되어 있는지 확인하는 필터다. 

***

## CsrfFilter 

CSRF란 서버로부터 인증을 하고 쿠키를 받은 사용자를 통해 대신 요청을 보내도록 하는 기법이다. 사용자는 공격자로부터 메일을 받던지 해서 공격자의 사이트로 이동하게 되고 공격자의 사이트에는 서버로 요청을 보내도록 설정되어 있다. 사용자는 이 사이트에서 행동을 하면 서버로부터 신뢰할 수 있는 쿠키 정보를 바탕으로 공격자 대신 요청 정보를 보내게 된다. 이는 사용자의 의도와는 무관하다. 

스프링 시큐리티는 이 CSRF 공격을 막기위한 CsrfFilter를 제공해준다. 해결 방법은 처음 요청부터 모든 요청까지 랜덤하게 생성된 토큰을 HTTP 피라미터로 사용자에게 전달해주고 매 요청마다 이 토큰 값을 가지고 와야한다.
 - 이 토큰 값은 클라이언트에서 이런식으로 전송된다. `<input type="hidden" name="${_csrf.parameterName}" value="${__csrf.token}" />`
 - HTTP PATCH, POST, PUT, DELETE 같은 메소드들은 이 토큰을 항상 첨부해야한다. 
 - Csrf Token을 꺼내올땐 HttpServletRequest 객체의 getHeader("X-CSRF-TOKEN") 메소드를 통해서 꺼내오거나    HttpServletRequest 객체의 getParameter("_csrf") 메소드를 통해서 꺼내온다. 이 정보가 서버에 있는 정보와 같은지 비교해서 판단한다.  

스프링 시큐리티에서는 기본적으로 http.csrf() 가 활성화되어 있다. http.csrf().disabled() 를 통해 비활성화 할 수 있다. 비활성화 하고나서 FilterChainProxy의 additionalFilters 에서 FilterChain 리스트를 보면 CsrfFilter 가 없는걸 볼 수 있다. 

***

## DelegatingFilterProxy

처음 요청을 받고 필터 처리를 하는 서블릿 필터는 스프링 컨테이너 기반의 필터가 아니다. 그러므로 스프링에서 정의된 빈을 주입해서 사용하는게 불가능하다. 

그러므로 특정한 이름을 가진 스프링 빈을 찾아서 그 빈에게 요청을 처리해줘야한다. 그래야지 스프링 기반의 필터 처리를 해줄 수 있다. 

- springSecurityFilterChain 이라는 이름을 가진 빈을 ApplicationContext 에서 찾아서 위임해준다. 그러므로 Servlet Filter 는 필터처리를 해주지 않는다.

스프링에서 FilterChainProxy 는 DelegatingFilterProxy 로 부터 요청을 위임받고 실제 보안처리를 해주는 스프링 빈이다. 여기서는 필터들을 관리하고 제어해주는 역할을 한다.

- 이는 스프링 시큐리티가 기본적으로 생성해주는 필터들을 관리해줄 수도 있지만 우리가 정의한 설정 클래스에서 추가한 필터들도 관리해준다. 

- FilterChainProxy 에서 필터를 순서대로 호출하면서 처리를 하고 마지막 필터까지 인증/인가 예외가 발생하지 않으면 보안이 통과하게 된다. 

***

## 필터 초기화와 다중 설정 클래스 

WebSecurityConfigurerAdapter (우리가 직접 설정한 SecurityConfig) 에서 설정한 정보인 RequestMatcher 와 보안 설정 그리고 필터 정보를 기반으로 SecurityFilterChain 이 생성되고 이는 FilterChainProxy 에 등록된다.

이는 WebSecurity 클래스에서 FilterChainProxy 에 등록시켜 준다. 
FilterChainProxy 가 각 필터를 가지고 있고 요청에 따라 RequestMatcher 와 매칭되는 필터가 작동한다. 

FilterChainProxy 는 사용자의 요청을 보고 각 URL 와 매치가 되는 SecurityFilterChain 을 선택하고 이를 적용시킨다. 

여러개의 Security Config 파일을 만들어서 사용할려면 @Order 에노테이션이 필요하다. 


***

## Authentication

Authentication 은 인증을 말하며 내가 누구인지를 증명하는 걸 말한다. 

스프링 시큐리니는 이런 인증을 토큰 개념으로 설면하는데 인증시 id 와 password 를 담고 인증 검증을 위해 전달되어서 사용한다.

인증 후 최종 인증 결과는 Security Context 에 저장되어서 전역적으로 참조가 가능하다. 

Authentication authentication = SecurityContextHolder.getContext().getAuthentication() 메소드를 통해 인증 객체를 참조하는게 가능하다. 

Authentication 인터페이스의 구현체로는 UsernamePasswordAuthenticationToken 과 AnonymousAuthenticationToken, RememberMeAuthenticationToken, TestingAuthenticationToken 등이 있다. 

물론 직접 이 인터페이스를 구현한 토큰을 만들수도 있다. 

Authentication 인터페이스 구조는 다음과 같은 정보를 포함하고 있다.

- principle: 사용자 아이디 혹은 User 객체를 저장한다. (자바에서 제공하는 인터페이스다.)

- credentials: 사용자 비밀번호를 말한다.

- authorities: 인증된 사용자의 권한 목록을 말한다.

- details: 인증 부가 정보를 말한다.

- Authenticated: 인증 여부를 말한다.  

Username 과 Password 를 통한 인증 플로우는 다음과 같다.

- 1. UsernamePasswordAuthenticationFilter 에서 유저가 전달한 정보를 바탕으로 Authentication 객체를 만든다. (이때 만드는 객체는 UsernamePasswordAuthenticationToken 이다.) 

  - 이 객체에 Principle 에는 Username 이 들어가고 Credential 에는 비밀번호가 들어가고 Authenticated 는 false 가 들어간다.
  
- 2. 인증 검증을 위해 이 Authentication 객체는 AuthenticationManager 에게 전달되고 인증 검증을 거친다. (AuthenticationManager 의 authenticate() 메소드를 통해 인증 검증을 거친다.)
AuthenticationManager 는 AuthenticationProvider 에게 이 작업을 위임한다. 

- 3. 인증이 실패하게 되면 인증 실패에 대한 예외가 발생하고 이를 처리하지만 인증에 성공하면 Authentication 객체에 Principle 에는 UserDetail 정보가 담기게 되고
Authorities 정보도 담기게 되고 Authenticated 는 true 가 된다.

- 4. 최종 Authentication 객체는 SecurityContext 에 저장되게 된다. 이를 통해 인증 객체를 전역적으로 사용하는게 가능해진다. 


***

## SecurityContextHolder

SecurityContext 는 Authentication 객체가 보관되는 장소로 필요하면 전역적으로 Authentication 객체를 꺼내어 쓸 수 있도록 설계된 클래스다.

ThreadLocal 에 저장되어 있기 때문에 아무곳에서나 참조가 가능하다. (ThreadLocal 은 Scope 단위로 변수를 저장하는게 아니라 스레드 단위로 변수를 저장할 수 있다. 이를 통해서 전역 참조가 가능하다)
(이는 스레드 전역 저장소로 다른 스레드에서 접근이 불가능하다. 그러므로 Thread-Safe 하다.)

SecurityContextHolder 는 SecurityContext 를 감싸고 있으며 감싸는 이유는 다양한 전략으로 SecurityContext 를 감쌀 수 있어서이다. 

감싸는 방식은 다음과 같다. 

- MODE_THREADLOCAL: 스레드당 SecurityContext 객체를 할당한다.  

- MODE_INHERITABLETHREADLOCAL: 메인 스레드와 자식 스레드에 관해서 동일한 SecurityContext 를 유지한다. 원래는 자식 스레드와 메인 스레드는 각각 별도의 ThreadLocal 을
가질 것이고 기본 전략은 Main 스레드에만 SecurityContext 를 유지하는 것이다. 

- MODE_GLOBAL: 응용 프로그램에서 단 하나의 SecurityContext 를 저장한다. 이 방식은 Thread Local 이 아니라 Static 변수에다가 저장하는 것이다.   

ThreadLocal 에 저장을 한 후 인증이 완료되면 HttpSession 에 저장되서 어플리케이션 전반에 걸친 전역적인 참조가 가능해진다. 

왜 이렇게 하냐면 Thread 자체는 많은 사용자 요청을 처리할 수 있다. 그러므로 HttpSession 에 있다가 요청이 들어오면 Thread 에서 SecurityContext 를 복사하고 
그 후 요청이 마무리 되면 다시 HttpSession 에 넣도록 하는 것 HttpSession 을 바로 이용하지 않는 것은 WebServer 마다 약간씩 다 다르기도 하고 글로벌해서 Thread-Safe 하지도 않다. 
 
그리고 SecurityContextHolder.clearContext() 를 통해서 초기화가 가능하다. (이는 인증에 실패하면 일어난다. 성공하면 SecurityContext 에 Authentication 을 넣어준다.) 

전략을 바꾸고 싶다면 SecurityContextHolder.setStrategyName() 을 통해서 가능하다.

***

## SecurityContextPersistenceFilter 

이 필터는 SecurityContext 객체를 생성하고 저장하고 조회하는 필터이다.

인증 전이면 HttpSecurityContextRepository 를 통해 새로운 SecurityContext 를 생성하고 이를 SecurityContextHolder 에 저장한다.  

그 후 인증 필터를 통해 인증을 하고 이를 통해 SecurityContext 에 Authentication 객체를 넣어준다. 

예로 익명 사용자의 요청의 경우에는 새로운 SecurityContext 를 생성하고 이를 SecurityContextHolder 에 저장하고  

그 후 AnonymousAuthenticationFilter 에서 AnonymousAuthenticationToken 을 이 SecurityContext 에 저장한다. 

인증을 하는 경우에는 (예로 폼을 들면) 새로운 SecurityContext 를 만들고 이를 Holder 에 넣어준다. 그 후 UsernamePasswordAuthenticationFilter 에서 UsernamePasswordAuthenticationToken 을 SecurityContext 에 저장해준다. 

그 후 최종 완료에는 Session 에 SecurityContext 를 저장한다. 

인증 후에는 새로운 SecurityContext 를 생성하지 않고 Session 에서 꺼내서 SecurityContextHolder 에 넣어준다. 
  
***

## Authentication Flow 

사용자가 인증을 하는 전체적인 처리 과정을 살펴보자. 

인증을 하는 필터는 유저가 요청한 정보를 바탕으로 Authentication 객체를 만들고 이를 AuthenticationManger 에게 전달한다.  
 
AuthenticationManger 는 실제적인 인증 처리를 AuthenticationProvider 에게 위임을 한다. 

AuthenticationManager 는 AuthenticationProvider 를 List 형태로 가지고 있고 인증을 할 때 이것들 중에서 하나씩 꺼내면서 Authentication 을 지원하는 Prodiver 인지 확인하고
이게 맞다면 이 Provider 가 인증처리를 하는 구조다.  

AuthenticationProvider 는 실제적인 유저 정보를 기반으로(Id 와 Password 정보) 인증 검증을 한다. 

유저가 요청한 정보와 실제 정보 (예를 들면 DB에 있는 유저 정보)와 비교를 해야한다. 이런 유저 정보를 가지고 오는 일은 AuthenticationProvider 의 retrieveUser() 메소드 안에서 UserDetailsService 의 loadUserByUsername(username) 메소드를 통해서 이뤄진다.

여기서 유저 정보를 찾을 수 없는 예외가 발생하면 이 작업을 시작한 필터에서 (여기선 UsernamePasswordAuthenticationFilter) 실패 핸들러를 호출해서 처리한다. 

성공하면 UserDetails 객체를 UserDetailsService 가 가져오고 추가적인 인증 검사를 한다. 

UserDetails 가 만료가 되었거나 Password 와 비교해서 검증을 한다. 이때 Password 가 맞지 않다면 BadCredentialException 예외가 발생한다. 
 
최종적으로 인증을 성공하면 UserDetails 정보와 UserDetails 에 있는 Authorities 정보를 바탕으로 Authentication 객체를 새로 만들어서 반환한다.

AuthenticationManager 는 이 반환받은 Authentication 객체를 필터에게 전달해주고 Filter 는 이를 SecurityContext 에 저장한다. 
    
AbstractUserDetailsAuthenticationProvider 를 보면 retrieveUser() 메소드를 통해 UserDetails 타입의 객체를 가져오고  이 객체 또는 이 객체의 Username 이 Principle 이 된다.

***

## AuthenticationManager

이 클래스는 필터로부터 인증 처리 지시를 받는 역할을 한다. 

AuthenticationManager 인터페이스의 구현체는 ProviderManager 이다. 

ProviderManager 는 AuthenticationProvider 리스트에서 확인을 하면서 인증 처리 요건에 맞는 AuthenticationProvider 를 찾아서 인증 처리를 위임한다.

AuthenticationProvider 는 자신이 처리할 수 있는 Authentication 이 맞다면 인증 처리를 시작한다. 

AuthenticationManager 는 현재 인증을 처리할 수 있는 AuthenticationProvider 를 찾을 수 없다면 부모 AuthenticationManager 에게 이를 처리해달라고 요청을 한다. 

 
***

## AuthenticationProvider

인증처리를 하는 가장 핵심적인 클래스. 

AuthenticationManager 에게 위임받아서 실제적인 인증처리를 하는 클래스다.

인증 처리를 완료하고 Authentication 객체를 실제로 만들어서 AuthenticationManager 에게 전달하는 처리를 한다. 

예상했다시피 AuthenticationProvider 는 인터페이스고 제공해주는 메소드는 딱 두개다.

- authenticate(): 실제 인증처리를 하는 메소드라고 생각하면 된다. 

- support(): 해당 구현체가 이 Authentication 객체에 대해 인증처리를 할 수 있는지의 여부를 말하는 메소드다. 

인증 과정은 UserDetailsService 로 부터 실제 사용자의 정보를 가지고 온다. 

이때 검증을 위해 UserDetails 타입으로 사용자 정보를 가지고온다. 

그 후 ID 검증, Password 검증, 사용자 계정 잠금 검증, 계정 비활성화 검증, 계정 만료 검증 등 다양한 검증을 한다. __(이 모든게 authenticate() 메소드안에서 이뤄지겠지.)__
 
- ID 가 null 이라면 UserNotFoundException 이 발생한다. 

- Password 가 다르다면 BadCredentialExcpetion 이 발생한다.

- 그 외 검증은 각각에 맞는 예외가 있다. 

***

## 인가 개념 및 필터 이해:Authorization, FilterSecurityInterceptor 

Authorization 은 인가를 말한다. 

인증을 성공한 후 너가 이 리소스 요청에 대한 적절한 권한이 있는지 검사하는 걸 말한다고 생각하면 된다.

스프링 시큐리티가 지원하는 권한 계층은 크게 3가지가 있다. 이 3가지에 대한 인가 처리를 지원해준다. 

- 웹 계층 

  - URL 요청에 따른 보안 
  
- 서비스 계층 

  - 화면 단위가 아닌 메소드 단위의 보안  
  
- 도메인 계층 

  - 객체 단위의 레벨을 말한다. 
  
여기서는 웹 계층과 서비스 계층만 다루겠다. 

### FilterSecurityInterceptor

마지막에 위치한 필터로 인증된 사용자의 요청에 인가 처리를 해서 요청의 승인 여부를 결정하는 필터다. 

인증 객체가 없이 이 필터 체인에 오면 AuthenticationException 이 발생한다. 

인증 후 자원에 접근하는 권한이 없다면 AccessDeniedException 이 발생한다. 

권한 제어 방식 중 HTTP 자원의 보안 처리를 하는 필터다. __(웹 계층과 관련된 보안 처리를 하네.)__

이 필터에서 인가 처리는 AccessDecisionManager 에게 맡긴다. 

FilterSecurityInterceptor 가 처리하는 플로우는 다음과 같다. 

1. 먼저 SecurityContextHolder 에서 Authentication 객체가 있는지 확인한다. __(인증을 한 유저인지 확인한다.)__ 여기서 인증 객체가 없으면 AuthenticationException 이 발생한다. 
이렇게 예외가 발생하면 ExceptionTranslationFilter 가 받아서 로그인 페이지로 이동하게 해서 인증 처리부터 하도록 오게 만든다.

2. 인증 객체가 있다면 SecurityMetadataSource 가 해당 URI 에 대한 접근 권한이 뭐가 있느지를 가지고 온다. __(해당 URI 에 접근하기 위해 필요한 권한이 무엇인지를 가지고 오는 역할을 하는 클래스네.)__

3. URI 에 대한 권한 정보가 null 이라면 누구라도 통과해도 된다는 뜻이므로 자원 접근을 허용해준다.

4. URI 에 대한 권한 정보가 있다면 AccessDecisionManger 에게 전달을 해주고 인가 처리를 맡긴다. 

5. AccessDecisionManager 는 내부적으로 인가 심사를 AccessDecisionVoter 에게 맡기게 되고 인가 통과 전략에 따라서 인가 처리를 마무리 한다. __(1명만 통과해도 되는지, 다수결인지, 만장일치인지. 이런 전략에 따라서 심사하는 걸 말한다.)__

6. 심사에 통과하면 자원 접근을 허용하고 통과하지 못하면 AccessDeniedException 을 발생시키고 ExceptionTranslationFilter 에게 전달해주는 역할을 한다. 

***

## 인가 결정 심의자: AccessDeniedManager, AccessDecisionVoter

AccessDecisionManager 는 인증정보, 권한정보, 요청정보를 이용해서 사용자의 자원 접근을 허용할 것인지 거부할 것인지 최종적으로 판단하는 클래스다. 

AccessDecisionManager 는 여러 개의 Voter 들을 가질 수 있고 Voter 들로부터 자원 접근에 허용, 거부, 보류에 해당하는 값을 받아서 판단을 한다. 

기본적으로 AccessDecisionManager 는 3가지 종류의 타입이 있고 승인을 허용하는 전략에 따라서 다르다.

- AffirmativeBased

  - 여러개의 Voter 들 중에서 하나만 승락해도 요청을 허용해주는 클래스다.
  
- ConsensusBased

  - 다수표를 통해서 최종 결정을 판단한다.
  
  - 동률일 경우 default 는 허용이다. 그치만 allowIfEqualGrantedDeniedDecision 값을 바꿔서 false 로 바꾸면 허용하지 않는다. 
  
- UnanimousBased

  - 만장일치를 통해서 결정을 한다.
  
### AccessDecisionVoter 

판단을 심사하는 역할을 한다. 

Voter 가 권한 부여 과정에서 판단하는 자료는 3가지다. 

- Authentication

  - 인증 정보를 말한다. 

- FilterInvocation

  - 요청 정보를 말한다. (antMatcher("/user")) 
  
- ConfigAttributes

  - 권한 정보를 말한다. (hasRole("USER"))
  
결정 방식은 다음과 같다. 

- ACCESS.GRANTED 

  - 접근 허용(1)

- ACCESS.DENIED

  - 접근 거부(-1)
  
- ACCESS.ABSTAIN

  - 접근 보류(0)