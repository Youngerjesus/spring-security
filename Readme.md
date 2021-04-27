# Spring Security
 
## 목차 
[1. 스프링 시큐리티 의존성 추가](#스프링-시큐리티-의존성이-추가되면-생기는-일) <br/>
[2. WebSecurityConfigurerAdapter](#WebSecurityConfigurerAdapter) <br/>
[3. HttpSecurity](#HttpSecurity) <br/>
[4. http.formLogin()](#http-formLogin) <br/>
[5. UsernamePasswordAuthenticationFilter](#UsernamePasswordAuthenticationFilter) <br/> 
[6. FilterChainProxy](#FilterChainProxy) <br/>
[7. Logout](#Logout) <br/>
[8. LogoutFilter](#LogoutFilter) <br/>
[9. RememberMe](#RememberMe) <br/> 
[10. RememberMeAuthenticationFilter](#RememberMeAuthenticationFilter) <br/> 
[11. AnonymousAuthenticationFilter](#AnonymousAuthenticationFilter) <br/> 
[12. 동시 세션 제어](#동시-세션-제어) <br/> 
[13. 세션 고정 보호](#세션-고정-보호) <br/> 
[14. 세션 정책](#세션-정책) <br/> 
[15. SessionManagementFilter](#SessionManagementFilter) <br/>
[16. ConcurrentSessionFilter](#ConcurrentSessionFilter) <br/>
[17. 권한설정과 표현식](#권한설정과-표현식) <br/> 
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







