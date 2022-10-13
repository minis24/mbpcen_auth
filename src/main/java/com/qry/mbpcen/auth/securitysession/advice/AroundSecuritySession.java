/**
 * 스프링 AOP 기반의 인증 처리 프로세스 처리 구현체
 * 타겟 메서드 Around 시 호출 (타겟 메서드실행 전/후 로 요청/응답 데이터 DB 적재) 처 
 * @author 김장관 (minis24@gmail.com)
 * @since 2018.02.05
 * @version 1.0
 * @see
 *
 * <pre>
 * << 개정이력(Modification Information) >>
 *   
 *   수정일      수정자           수정내용
 *  -------    --------    ---------------------------
 *   2018.02.05  김장관          최초 생성
 *
 * </pre>
 */



package com.qry.mbpcen.auth.securitysession.advice;
import java.util.Enumeration;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;


@Component
@Aspect
@Order(10)
public class AroundSecuritySession {
	private final Log logger = LogFactory.getLog(getClass());
	
	/** Service */

	
	
	
	@Around( "PointCutSet.around_securitysession()")
	public String securitySession(ProceedingJoinPoint jp  ) throws Throwable{
		logger.info( "\r\n\r\n\r\n\r\n\r\n\r\n" +
				"===================================================================================================\r\n" + 
				"* NEW REQUEST START ["  +this.getClass().getSimpleName()+"."+ new Object() {}.getClass().getEnclosingMethod().getName() + "]\r\n"+
				"===================================================================================================\r\n");
		
		long start_time = System.currentTimeMillis();
		
		ServletRequestAttributes requestAttr = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
		HttpServletRequest request = requestAttr.getRequest();		
		HttpSession session = request.getSession();
		String sess_id = session.getId();
		

		
		//*******************************************************************************************************
		// * 헤더 출력 
		//*******************************************************************************************************
		StringBuffer request_header = new StringBuffer();
		request_header.append("\r\n")
					  .append("---------------------------------------\r\n")
				      .append("[HEADER PRINT]\r\n")
				      .append("---------------------------------------").append(" \r\n");
		Enumeration<String> names = request.getHeaderNames();
		while (names.hasMoreElements()) {
		    String name = (String)names.nextElement();
		    String value = request.getHeader(name);
		    request_header.append(name).append("=").append(value).append(" \n");
		}

		logger.debug(request_header);
		
		
		
		
		//*******************************************************************************************************
		// * 파라미터 확인 
		//*******************************************************************************************************
		Object[] args = jp.getArgs();
		
		
		
		
		//*******************************************************************************************************
		// * 타겟 메서드 실행 
		//*******************************************************************************************************
		logger.info( "\r\n\r\n" +
				"===================================================================================================\r\n" + 
				"* START TARGET METHOD - REQUEST_URI : [ "+request.getRequestURI()+ " ] \r\n" + 
				"===================================================================================================\r\n" + 
				" - SESSION_ID    : [" +sess_id+"] \r\n" +
				" - CONTROLLER    : [" +jp.getTarget() + "]\r\n" +
				" - METHOD        : [" +jp.getSignature().toShortString() +"]\r\n" +
				"===================================================================================================\r\n");
		
		
		String returnValue = (String)jp.proceed();
//		ModelAndView returnValue = (ModelAndView)jp.proceed(createDecryptArgs());
		
		logger.info("\r\n\r\n"
				+ "===================================================================================================\r\n"
				+ "* END TARGET METHOD - REQUEST_URI : [ " + request.getRequestURI() + " ] \r\n"
				+ "===================================================================================================\r\n"
				+ " - SESSION_ID    : [" + sess_id + "] \r\n" 
				+ " - CONTROLLER    : [" + jp.getTarget() + "]\r\n"
				+ " - METHOD        : [" + jp.getSignature().toShortString() + "]\r\n"
				+ "===================================================================================================\r\n");
		
		
		
		
		
		
		
		
		
		
		//*******************************************************************************************************
		// * 응답데이터 생성 
		//*******************************************************************************************************
		
		
		
		
		
		logger.info( "\r\n\r\n" +
				"===================================================================================================\r\n"  
				+ "* REQUEST END ["  +this.getClass().getSimpleName()+"."+ new Object() {}.getClass().getEnclosingMethod().getName() + "]\r\n"
				+ "===================================================================================================\r\n"
				+ " - PERFORMANCE_TIME : [" +(System.currentTimeMillis() - start_time)+"] \r\n" 
				+ "===================================================================================================\r\n");
		

	
	
		
		return returnValue;

		
		
		
		
		
	
	}
	

	
	


	/**
	 * 보안프로세스 구현시 수행하는 메서드 
	 * args 에서 request_body 를 복호화하여 전달한다.
	 * 현재는 보안세션 미구현상태이므로 받은 파라미터 그대로 리턴한다.
	 * @param args
	 * @return
	 */
	private Object[] createDecryptArgs(Object[] args) {
		return args;
	}



}
