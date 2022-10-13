package com.qry.mbpcen.auth.securitysession.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.resource.VersionResourceResolver;

import com.qry.mbpcen.auth.ExecuteTimeInterceptor;


//===================================================================
//spring boot에서는 static file을 기본으로는 resource 디렉터리 내의 static이라는 폴더를 찾아서 제공을 해준다. 
//때문에 static이라는 폴더를 찾아서 설정을 해준다면 무리없이 정적 파일이 잘 제공되는 것을 볼 수 있다. 
//하지만, 세상을 살다보면 내 뜻대로 정적 파일의 경로를 변경할 필요성이 생길때도 있을 수 있는 법! 
//이럴때는 두 가지 방법이 존재한다.
//--------------------------------------------------------------------
//1. application.properties를 이용한 설정
//--------------------------------------------------------------------
// #spring.mvc.static-path-pattern=/static/** (static 리소스의 공통된 패턴 정의)
// spring.resources.static-locations=classpath:WEB-INF/
// spring.resources.add-mappings=true

//--------------------------------------------------------------------
//2. @EnableWebMvc와 WebMvcCongiure를 이용한 환경설정
//--------------------------------------------------------------------
// 
//===================================================================
@Configuration
public class WebConfig implements WebMvcConfigurer{

	@Bean
	public ExecuteTimeInterceptor executeTimeInterceptor() {
		return new ExecuteTimeInterceptor();
	}
	
	//===================================================================
	// Interceptor 등록 
	//===================================================================		
	@Override
	public void addInterceptors(InterceptorRegistry registry) {
		registry.addInterceptor(executeTimeInterceptor())
				.addPathPatterns("/**")
				.excludePathPatterns("/"); 
	}
	
	
	@Override
	public void addResourceHandlers(ResourceHandlerRegistry registry) {
		registry.addResourceHandler("/assets/**","/webjars/**") //호출경로로 사용되는 URI 
				.addResourceLocations("classpath:/assets/","/assets/","/webjars/") //실제 파일이 위치할 폴더 경
				.setCachePeriod(60 * 60 * 24 * 365) //1년 
//				.setCachePeriod(1)
				//===================================================================
				//별도의 설정이 없으면 PathResourceResolver가 동작하는데
				//resourceChain을 true 로 설정하면 추가 적용을 할 수 있다.
				// VersionResourceResolver().addContentVersionStrategy :
				//   --> 웹브라우저에서 웹리소스 로드시 /main-er323sdf23523sdlfk2.css 같이 적용된다.
				//===================================================================
				.resourceChain(true)
				.addResolver(new VersionResourceResolver().addContentVersionStrategy("/**"));  
	}
	
	
	
	//===================================================================
	// 페이지에 데이터 전달없이 URL연결만 할경우 
	// 1. 매핑 URL을 addViewController의 파라미터로 설정하고
	// 2. 페이지이름을 setViewName에 파라미터로 설정하면 된다. 
	//===================================================================	
	@Override
	public void addViewControllers(ViewControllerRegistry registry) {
//		registry.addViewController("/test")
//				.setViewName("thymeleaf/home");
		
//		registry.addViewController("/error").setViewName("thymeleaf/etc/404");
	}
	
	
//	@Override
//    public void addCorsMappings(CorsRegistry registry) {
//        registry.addMapping("/**")
//                .allowedOrigins("http://a.com:5500")
//                .allowedMethods("GET","POST","DELETE","PUT")
//                .allowCredentials(true);
//    }

}
