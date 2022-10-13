package com.qry.mbpcen.auth.securitysession.advice;

import org.aspectj.lang.annotation.Pointcut;

public final class PointCutSet {

	private PointCutSet() {}


//	@Pointcut("execution( * com.brilliantts.fuzepay.app.api.controller.FuzePayAppController.G001(..)) || "
//			+ "execution( * com.brilliantts.fuzepay.app.api.controller.FuzePayAppController.G002(..))" )
	
	
	
	
	/**
	 * Around ALL View에 대한 Advice
	 */
	@Pointcut(
			"execution( "
			+ "public "
			+ "String "
			+ "com.qry.mbpcen.auth..controller"
			+ ".*Controller"
			+ ".*(..))" 
		)
	public void around_securitysession(){}
	
	
	
}
