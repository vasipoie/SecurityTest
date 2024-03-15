package kr.or.ddit.security;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

public class CustomLoginSuccessHandler implements AuthenticationSuccessHandler{

	private static final Logger log = LoggerFactory.getLogger(CustomLoginSuccessHandler.class);
	
	private RequestCache requestCache = new HttpSessionRequestCache();
	
	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException, ServletException {
		
		log.info("## 로그인 성공~! Login Success");
		
		User customUser = (User) authentication.getPrincipal();
		
		//인증이 완료된 사용자 ID 꺼내기
		log.info("유저네임 username : " + customUser.getUsername());
		//인증이 완료된 사용자 PW 꺼내기
		log.info("비번 password : " + customUser.getPassword());
		
		//세션에 등록되어 있는 인증 과정에서 발생한 에러 정보를 삭제
		clearAuthenticationAttribute(request);
		
		SavedRequest savedRequest = requestCache.getRequest(request, response);
		
		String targetUrl = "/";
		
		if(savedRequest != null) { //타겟 정보가 존재함
			
			targetUrl = savedRequest.getRedirectUrl();
			
		}
		
		log.info("타겟url Login Success targetUrl : " + targetUrl);
		
		response.sendRedirect(targetUrl);
		
	}

	private void clearAuthenticationAttribute(HttpServletRequest request) {
		
		HttpSession session = request.getSession();
		
		if(session == null) {
			return;
		}
		
		session.removeAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
	}
	

}
