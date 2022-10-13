package com.qry.mbpcen.auth.securitysession.controller;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Enumeration;
import java.util.concurrent.atomic.AtomicLong;

import javax.annotation.Resource;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.xml.bind.DatatypeConverter;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import com.qry.mbpcen.auth.securitysession.service.RSAService;



//===================================================================
//@RestController 어노테이션의 역할 (스프링 4부터 추가)
//@ResponseBody 어노테이션과 @Controller 어노테이션을 합쳐서 만든 어노테이션
//  --> @ResponseBody 어노테이션이 있으면 실행결과는 View를 거치지 않고 Http ResponseBody에 직접 입력된다.
//  --> MappingJacksonHttMessageConverter를 통해 Json으로 결과가 표현된다.
//===================================================================
@RestController
@RequestMapping(value = "/ss")
public class SecuritySessionController {
    private final Log logger = LogFactory.getLog(getClass());
    
    
	/** Service */
	/** RSA Service */
	@Resource(name = "RSA_SERVICE")
	protected RSAService rsaSercice;
    
    

	/**
	 * 공개키 요청 
	 * @return
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeySpecException 
	 */
	//============================================================================
	//SOA(Same Origin Architecture) 정책 해결방법 
	// [도메인 출처가 다를 경우 보안정책상 자격증명은 서버로 전송이 안됨, 브라우저에서 요청시 쿠키값은 무시된다.]
	//------------------------------------
	// (1) 첫번째 방법 : 어노테이션으로 CORS 적용 
	//------------------------------------
	// 아래 예제는 '모든 도메인'이 아닌 '특정 도메인'만 허용하는 예제이다.
	//@CrossOrigin 어노테이션은 여러 Properties를 가지고 있다. 그 중, origins는 허용할 도메인을 나타낸다.
	//복수개일 경우 콤마로 구분하여 넣어주면 된다.
	//  @CrossOrigin(origins = "http://domain1.com, http://domain2.com")
	//	@CrossOrigin --> 모든 도메인의 요청 허용 
	//	@CrossOrigin(origins = "http://a.com:5500")  --> 특정 도메인의 요청 허용 
	//------------------------------------
	// (2) 두번째 방법 : response 헤더에 정책 설정하여 리턴 
	//------------------------------------
	//	response.setHeader("Access-Control-Allow-Origin","http://a.com:5500");
	//	response.setHeader("Access-Control-Allow-Credentials","true");
	//------------------------------------
	// (3) 세번째 방법 : WebMvcConfigurer 에 글로벌하게 설정   (보안에 취약함) 
	//------------------------------------		
	//	@Override
	//  public void addCorsMappings(CorsRegistry registry) {
	//      registry.addMapping("/**")
	//              .allowedOrigins("http://a.com:5500")
	//              .allowedMethods("GET","POST","DELETE","PUT")
	//              .allowCredentials(true);   -->true 로 설정하면 보안에 취약하므로 특정한 상황에서만 설정.
	//  }
	//============================================================================
	
//	@CrossOrigin 
//	@CrossOrigin(origins = "http://a.com:5500")  
	@RequestMapping(value = "/step1" )
	public String step1() throws NoSuchAlgorithmException, InvalidKeySpecException  {
		ServletRequestAttributes requestAttr = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
		HttpServletRequest request = requestAttr.getRequest();	
		HttpServletResponse response = requestAttr.getResponse();
		HttpSession httpSession = request.getSession();
		String sess_id = httpSession.getId();
		
		
		//*******************************************************************************************************
		// * RSA Keypair 생성 
		//*******************************************************************************************************	
		KeyPair keyPair = rsaSercice.generateKeyPair(2048);
		PublicKey  mPubKey = keyPair.getPublic();
		PrivateKey mPriKey = keyPair.getPrivate();
		
		
		//*******************************************************************************************************
		// * 개인키 세션에 저장 
		//*******************************************************************************************************	
		httpSession.setAttribute("RSA_PRIVATE_KEY", mPriKey);
		

		
		//*******************************************************************************************************
		// * 클라이언트로 내려줄 공개키 추출 
		//  - 공개키는 Modulous 값,Exponent 값 으로 구성 --> 클라이언트에서는 이 값으로 공개키 획득 
		//*******************************************************************************************************	
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		RSAPublicKeySpec publicSpec = keyFactory.getKeySpec(mPubKey, RSAPublicKeySpec.class);
        String publicKeyModulus = publicSpec.getModulus().toString(16);
        String publicKeyExponent = publicSpec.getPublicExponent().toString(16);

		
		/*[설 명]
		 * 1. json-simple는 google에서 제공해주는 json사용 라이브러리 입니다
		 * 2. jsonObject.put(key, value); 형태로 데이터를 삽입합니다
		 * 3. jsonObjectParse.get(key); 형태로 데이터를 추출합니다
		 * 4. jsonArray.add(value); 형태로 데이터를 삽입합니다
		 * 5. jsonArray.get(배열 번지); 형태로 데이터를 추출합니다
		 * 6. JSONParser 는 json 데이터 파싱을 도와주는 객체입니다
		 * */
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("RSAModulus", publicKeyModulus);
		jsonObject.put("RSAExponent", publicKeyExponent);
		
		
		return jsonObject.toJSONString();
	}
	
	
	
	
	/**
	 * step1 의 공개키로 암호화된 데이터를 세션에 저장된 개인키로 복호화 후 리턴한다. (테스트 검증용) 
	 * @return 복호화 문 
	 */
//	@CrossOrigin(origins = "http://a.com:5500")
	@RequestMapping(value = "/test_v" , produces ="application/json; charset=utf-8", method=RequestMethod.POST)
	public String test_v( @RequestBody(required=true) String request_body) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, ParseException {
		ServletRequestAttributes requestAttr = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
		HttpServletRequest request = requestAttr.getRequest();	
		HttpSession httpSession = request.getSession();
		String sess_id = httpSession.getId();
		
		
		logger.debug("request_body : " +request_body);
		
		
		JSONParser parser = new JSONParser();
		JSONObject requestBody = (JSONObject)parser.parse(request_body);
		
		String encStr = (String)requestBody.get("encryptString");
		byte[] encByte = DatatypeConverter.parseHexBinary(encStr);
		PrivateKey mPriKey = (PrivateKey)httpSession.getAttribute("RSA_PRIVATE_KEY");

		
		byte[] decByte = rsaSercice.doRSAPriKeyDecrypt(mPriKey, encByte);
		String decStr = DatatypeConverter.printHexBinary(decByte);
		
		
		/*[설 명]
		 * 1. json-simple는 google에서 제공해주는 json사용 라이브러리 입니다
		 * 2. jsonObject.put(key, value); 형태로 데이터를 삽입합니다
		 * 3. jsonObjectParse.get(key); 형태로 데이터를 추출합니다
		 * 4. jsonArray.add(value); 형태로 데이터를 삽입합니다
		 * 5. jsonArray.get(배열 번지); 형태로 데이터를 추출합니다
		 * 6. JSONParser 는 json 데이터 파싱을 도와주는 객체입니다
		 * */
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("decryptString", decStr);
		
		
		return jsonObject.toJSONString();
	}
	
	
	
	/**
	 *  세션키 저장 
	 * @return 복호화 문 
	 */
	@CrossOrigin
	@RequestMapping(value = "/step2" , produces ="application/json; charset=utf-8", method=RequestMethod.POST)
	public String step2( @RequestBody(required=true) String request_body) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, ParseException {
		ServletRequestAttributes requestAttr = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
		HttpServletRequest request = requestAttr.getRequest();	
		HttpSession httpSession = request.getSession();
		String sess_id = httpSession.getId();
		
		
		logger.debug("request_body : " +request_body);
		
		
		JSONParser parser = new JSONParser();
		JSONObject requestBody = (JSONObject)parser.parse(request_body);
		
		String encStr = (String)requestBody.get("encryptString");
		byte[] encByte = DatatypeConverter.parseHexBinary(encStr);
		PrivateKey mPriKey = (PrivateKey)httpSession.getAttribute("RSA_PRIVATE_KEY");

		
		byte[] decByte = rsaSercice.doRSAPriKeyDecrypt(mPriKey, encByte);
		String decStr = DatatypeConverter.printHexBinary(decByte);
		
		
		/*[설 명]
		 * 1. json-simple는 google에서 제공해주는 json사용 라이브러리 입니다
		 * 2. jsonObject.put(key, value); 형태로 데이터를 삽입합니다
		 * 3. jsonObjectParse.get(key); 형태로 데이터를 추출합니다
		 * 4. jsonArray.add(value); 형태로 데이터를 삽입합니다
		 * 5. jsonArray.get(배열 번지); 형태로 데이터를 추출합니다
		 * 6. JSONParser 는 json 데이터 파싱을 도와주는 객체입니다
		 * */
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("decryptString", decStr);
		
		
		return jsonObject.toJSONString();
	}
	
}
