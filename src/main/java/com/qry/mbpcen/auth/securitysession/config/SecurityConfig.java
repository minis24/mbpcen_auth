package com.qry.mbpcen.auth.securitysession.config;


import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;


//===================================================================
//In Spring Security 5.7.0-M2 we deprecated the WebSecurityConfigurerAdapter
// , as we encourage users to move towards a component-based security configuration.
// 기존에는 WebSecurityConfigurerAdapter를 상속받아 설정을 오버라이딩 하는 방식이었는데 
// 바뀐 방식에서는 상속받아 오버라이딩하지 않고 모두 Bean으로 등록을 합니다.
//===================================================================
@Configuration
@EnableWebSecurity
public class SecurityConfig {
	private final Log logger = LogFactory.getLog(getClass());
	
//===================================================================
//기존 방식에서는 메서드를 오버라이딩해서 설정을 하고 클래스 내부에 설정 정보를 저장하는 방식인 듯 합니다.
//바뀐 방식에서는 모든것들을 Bean으로 등록해서 스프링 컨테이너가 관리할 수 있도록 변경이 된 듯 합니다.
//반환 값이 void에서 설정 유형으로 변경되었습니다.
//그에 따라 return을 해줘야 되겠죠? (http.build())	
//===================================================================	
	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		logger.info( "\r\n\r\n\r\n\r\n\r\n\r\n" +
				"===================================================================================================\r\n" + 
				"* CONFIG-SPRING SECURITY ["  +this.getClass().getSimpleName()+"."+ new Object() {}.getClass().getEnclosingMethod().getName() + "]\r\n"+
				"===================================================================================================\r\n");
		
	
		http
			.authorizeRequests()
			
			//===================================================================
			//서버를 클라우드에 올리는 경우, 일반적으로 로드밸런서를 사용중이라면 로드밸런서에 상태 체크 url을 작성해야 합니다. 
			//이런 경우 스프링 시큐리티에서 인증을 진행하지 않아야만 정상적으로 처리가 가능합니다. 
			//이처럼 로그인 없이 접근 가능해야하는 URI는 SpringSecurityConfig에 
			//'.antMatchers("/chk").permitAll()'와 같이 예외를 설정할 수 있습니다.
			//===================================================================
			.antMatchers("/views/joinPage", "/views/joinProcess").permitAll()
			.antMatchers("/ss/**").permitAll()    // test page
			.antMatchers("/").permitAll()    // test page
//	 		.antMatchers("/test/**").permitAll()    // test page
//	 		.antMatchers("/error").permitAll()    // test page
//	 		.antMatchers("/views/loginPage").permitAll()   
			
			
			//===================================================================
			//어떤 요청이 들어오든 인증을 받도록 강제해 줄 수 있다.
			////어떠한 URI로 접근하던지 인증이 필요함을 설정합니다.
			//===================================================================
			.anyRequest().authenticated()
			
	 		//===================================================================
	 		//antMatchers("/manage").hasAuthority("ROLE_ADMIN")' 부분처럼 처리하면 됩니다. 
	 		//그럼 해당 사용자가 ADMIN의 role을 가지고 있어야만 '/manage' 이하의 uri에 접근 가능하게 됩니다. 
	 		//ROLE은 DB에 넣어두면 되겠죠.
	 		//===================================================================
//	 		.antMatchers("/manage").hasAuthority("ROLE_ADMIN")
			
			
			
			//===================================================================
			//login form 설정 
			//===================================================================
			.and()
			.formLogin().disable()         //기본 로그인 페이지 없애기
			.formLogin()                   //.formLogin()'에서 폼방식 로그인을 사용할 것임을 알리고,
	    	.loginPage("/views/signin")    //.loginPage("/view/login")' 에서 커스텀 페이지로 로그인 페이지를 변경합니다.
	    	//===================================================================
	    	//loginProcessingUrl("/loginProc")' 은 별도로 Controller에 만들어야 하는게 아니고, 
	    	//formLogin 방식이므로 해당 주소를 어디로 처리할지 정해주는 겁니다. 
	    	//그럼 저 '/view/login'에서 '<form method="post" action="/loginProc">'와 같이 form의 action을 정해주면 
	    	//알아서 스프링 시큐리티쪽으로 id와 pw를 보내게 됩니다.
	    	//===================================================================
	    	.loginProcessingUrl("/views/signinAction")
	        .usernameParameter("userID")
	        .passwordParameter("userPW")
	    	.defaultSuccessUrl("/views/mnu/list", true).permitAll()
	    	
	    	
	    	
	    	.and()
//			.logout().disable()
			.logout()              // logout도 필요하니 logout도 추가해줍니다.
			//===================================================================
			//.logoutRequestMatcher(new AntPathRequestMatcher("/logoutProc"))' 부분 처럼 처리하면 
			//'/logoutProc'을 호출할 시 로그아웃이 되고, 그럼 인증된게 사라지니 다시 로그인 페이지로 자동으로 이동되게 되는 것입니다. 
			//이 부분은 생략 가능해서 이렇게 서브로 넣었습니다. 생략 시 default로 '/logout' 호출 시 로그아웃이 가능합니다.
			//===================================================================
			.logoutRequestMatcher(new AntPathRequestMatcher("/logoutProc"))  

			
			
			
	    	//===================================================================
			//CSRF(Cross Site Request Forgery)는 특정 사용자를 대상으로 하지 않고, 
			//불특정 다수를 대상으로 로그인된 사용자가 자신의 의지와는 무관하게 공격자가 의도한 행위(수정, 삭제, 등록, 송금 등)를 하게 만드는 공격이다.
	    	//===================================================================
	    	.and()
			.csrf().disable()
			
			//===================================================================
			//클라이언트에서 CSRF 토큰 획득 방법 
			//방법 1)서버가 HTML 렌더링 시 meta태그에 토큰 집어넣기 
			// <meta name="csrf-token" content="{{#_csrf}}token{{/_csrf}}">
			//방법 2) 서버가 HTML 렌더링 시 form태그에 hidden _csrf 필드 집어넣기 
			// <input type="hidden" name="_csrf" value="{{#_csrf}}token{{/_csrf}}" />
			//방법 3) 서버의 API 호출하기 
			// RESTful 서버는 뷰 렌더링을 하지 않으므로 CSRF토큰을 획득 할 수 있는 별도 API를 클라이언트에게 제공함 
			//  (1) 헤더 
			
			
			
//			.csrf();
			
			
//			.headers().disable()
//			.httpBasic().disable()
//			.rememberMe().disable()
//
//			.sessionManagement()
//			.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
//			.and()
//			.exceptionHandling() ;
//			.accessDeniedHandler(accessDeniedHandler())
//			.authenticationEntryPoint(authenticationEntryPoint())
//			.and()
//			.addFilterBefore(jwtAuthenticationFilter(jwt, tokenService), UsernamePasswordAuthenticationFilter.class);

		
		;
		
		
		
		return http.build();
	}
	
	

//===================================================================	
//css나 이미지 파일 등의 경우 인증이 되지 않은 상태에서도 보여져야 하는 경우가 대부분이다.
//이 경우 별도로 WebSecurity 하나를 인자로 갖는 configure를 오버라이딩해서 예외 처리를 할 수 있습니다.
//WebSecurity Configure도 마찬가지 입니다. 
//WebSecurityCustomizer를 Bean으로 등록해서 설정을 하면 됩니다.	
//===================================================================	
	@Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
		logger.info( "\r\n\r\n\r\n\r\n\r\n\r\n" +
				"===================================================================================================\r\n" + 
				"* CONFIG-SPRING SECURITY ["  +this.getClass().getSimpleName()+"."+ new Object() {}.getClass().getEnclosingMethod().getName() + "]\r\n"+
				"===================================================================================================\r\n");
		
        return (web) -> web.ignoring().antMatchers("/assets/**", "/h2-console/**","/api/hello2");
    }
	
	

    
    
	// ===================================================================
	// AuthenticationManagerBuilder를 인자로 갖는 configure를 추가해줬습니다.
	// 저렇게 설정하면 이제 유저가 id와 pw를 입력한 후 form이 발송되면 LoginIdPwValidator 쪽으로 id가 넘어가 비교할 수
	// 있게 됩니다.
	// ===================================================================
//    @Override
//    public void configure(AuthenticationManagerBuilder auth) throws Exception {
//        auth.userDetailsService(loginIdPwValidator);
//    }

}
