package kr.or.ddit.security;

public class SecurityController {
	/*
	 * 18장. 스프링 시큐리티
	 * 
	 * 1. 스프링 시큐리티 소개
	 * 	- 애플리케이션에서 보안 기능을 구현하는데 사용되는 프레임 워크이다.
	 *  - 스프링 시큐리티는 필터 기반으로 동작하기 때문에 스프링 MVC와 분리되어 동작한다.
	 *  
	 *  	# 기본보안 기능
	 *  	
	 *  	- 인증(Authentication)
	 *  		> 애플리케이션 사용자의 정당성을 확인한다.
	 *  	- 인가(Authorization)
	 *  		> 애플리케이션의 리소스나 처리에 대한 접근을 제어한다.
	 *  
	 *  	# 시큐리티 제공 기능
	 *  
	 *  		- 세션 관리
	 *  		- 로그인 처리
	 *  		- CSRF 토큰 처리
	 *  		- 암호화 처리
	 *  		- 자동 로그인
	 *  
	 *  		** CSRF 용어 설명
	 *  		- 크로스 사이트 요청 위조는 웹 사이트 취약점 공격의 하나로, 사용자가 자신의 의지와는 무관하게
	 *  		공격자가 의도한 행위(수정, 삭제, 등록 등)를 특정 웹 사이트에 요청하게 하는 공격을 말한다.
	 *  
	 *  		> CSRF 공격을 대비하기 위해서는 스프링 시큐리티 CSRF Token을 이용하여 인증을 진행한다.
	 *  
	 *  	# 시큐리티 인증 구조
	 *  		
	 *  		클라이언트에서 타겟으로 돌아가기 위해 요청을 진행한다. 이때, 타겟에 설정되어 있는 요청 접근
	 *  		권한이 '사용자' 등급일때로 설정되어 있다고 가정하자.
	 *  		타겟으로 접근하기 위한 요청을 날렸고 요청 안에 사용자 등급에 해당하는 인가 정보가
	 *  		포함되어 있지 않으면 스프링 시큐리티는 인증을 진행할 수 있도록
	 *  		인증 페이지(로그인 페이지)를 제공하여 사용자에게 인증을 요청한다.
	 *  		사용자는 아이디, 비밀번호를 입력 후 인증을 요청한다.
	 *  		클라이언트에서 서버로 요청한 HttpServletRequest의 요청 객체를
	 *  		AuthenticationFilter가 요청을 intercept한다.
	 *  		UsernamePasswordAuthenticationToken을 통해 인증을 진행할 토큰을 만들어
	 *  		AuthenticationManager에게 위임한다.
	 *  		넘겨받은 id, pw를 이용해 인증을 진행하는데 성공 시, Authentication 객체 생성과 성공을
	 *  		전달하고, 실패하면 Exception 에러를 발생시킨다. 인증에 성공 전 만들어진 Authentication
	 *  		객체를 AuthenticationProvider에게 전달하고 UserDetailService에서 넘겨받은
	 *  		Authentication 객체 정보를 이용해서 Database에 일치하는 회원정보를 조회하여 꺼낸다.
	 *  		꺼낸 정보를 UserDetails로 만들고 최종 User객체에 회원정보가 등록된다.
	 * 			등록이 되면서 User Session 정보가 생성된다. 이후 스프링 시큐리티 내 SecurityContextHolder(시큐리티 Inmemory)에 UserDetail 정보를 저장한다
	 * 			그리고 최종 쿠키로 만들어진 JESESSIONID가 유효한지를 검증 후 유효하면 인증을 완료하고 타겟으로 진입한다.
	 *
	 *
	 * 	2. 스프링 시큐리티 설정
	 *
	 * 		# 환경 설정
	 * 		
	 * 			- 의존 라이브러리 설정(pom.xml 설정)
	 * 				> spring-security-web
	 * 				> spring-security-config
	 * 				> spring-security-core
	 * 				> spring-security-taglibs
	 *
	 * 		# 웹 컨테이너 설정(web.xml 설정)
	 *
	 * 			- 스프링 시큐리티가 제공하는 서블릿 필터 클래스를 서블릿 컨테이너에 등록한다. (web.xml)
	 * 			- 스프링 시큐리티는 필터 기반이므로 시큐리티 필터체인을 등록한다.
	 * 				> context-param 태그의 param-value 추가
	 * 				(추가 파라미터 : /WEB-INF/spring/security-context.xml)
	 * 				> SpringSecurityFilterChain 추가
	 *
	 * 		# 스프링 시큐리티 설정
	 *
	 * 			- 스프링 시큐리티 컴포넌트를 빈으로 정의한다.
	 * 			- spring/security-context.xml 설정
	 *
	 * 		# 웹 화면 접근 정책
	 *
	 * 			- 웹 화면 접근 정책을 정한다. (테스트를 위한 각 화면당 접근 정책을 설정한다.)
	 *
	 * 				대상			│	화면		│	접근 정책		
	 * 			──────────────────────────────────────────────────────────────────────
	 * 			일반 게시판		│	목록화면	│	모두가 접근 가능하다
	 * 							│	등록화면	│	로그인한 회원만 접근 가능하다
	 * 			──────────────────────────────────────────────────────────────────────
	 * 			공지사항 게시판	│	목록화면	│	모두가 접근 가능하다.
	 * 							│	등록화면	│	로그인한 관리자만 접근 가능하다
	 * 			──────────────────────────────────────────────────────────────────────
	 *
	 * 		# 화면 설명
	 *
	 * 			- 컨트롤러
	 * 				> controller.BoardController
	 * 				> controller.NoticeController
	 *
	 * 			- 화면 페이지
	 * 				> /security/board/list
	 * 				> /security/board/register
	 * 				> /security/notice/list
	 * 				> /security/notice/register
	 * 		
	 *  3. 접근 제한 설정
	 *  - 시큐리티 설정을 통해서 특정 URI에 대한 접근을 제한할 수 있다.
	 *  
	 *  	# 환경 설정
	 *  		
	 *  		- 스프링 시큐리티 설정
	 *  		> URI 패턴으로 접근 제한을 설정한다.
	 *  		> security-context.xml 설정
	 *  			- <security:intercept-url pattern="/board/list" access="permitAll" />
	 *  			- <security:intercept-url pattern="/board/register" access="hasRole('ROLE_MEMBER')" />
	 * 			
	 * 		# 화면 설정
	 * 		
	 * 			- 일반 게시판 목록 화면(모두 접근 가능하도록 되어있다 : permitAll)
	 * 			- 일반 게시판 등록 화면(회원권한을 가진 사용자만 접근 가능 : hasRole('ROLE_MEMBER'))
	 * 				> 접근 제한에 걸려 스프링 시큐리티가 기본적으로 제공하는 로그인 페이지로 이동합니다.
	 * 			- 공지사항 게시판 목록 화면(모두 접근 가능하도록 되어있다 : permitAll)
	 * 			- 공지사항 게시판 등록 화면(관리자 권한을 가진 사용자만 접근 가능 : hasRole('ROLE_ADMIN'))
	 * 				> 접근 제한에 걸려 스프링 시큐리티가 기본적으로 제공하는 로그인 페이지로 이동합니다.
	 * 
	 * 
	 * 	4. 로그인 처리
	 * 	- 메모리상에 아이디와 패스워드를 저장하고 로그인을 처리한다.
	 * 	- 스프링 시큐리티 5버전부터는 패스워드 암호화 처리기를 반드시 이용하도록 변경이 되었다.
	 * 	- 암호화 처리기를 사용하지 않도록 "{noop}" 문자열을 비밀번호 앞에 사용한다.
	 * 
	 * 		# 환경설정
	 * 		
	 * 			- 스프링 시큐리티 설정
	 * 				> security-context.xml 설정		
	 * 			<security:authentication-manager>
	 * 				<security:authentication-provider>
	 * 					<security:user name="member" password="{noop}1234"
	 * 						authrities="ROLE_MEMBER" />
	 * 				</security:authentication-provider>
	 * 			</security:authentication-manager>
	 * 
	 * 		# 화면 설명
	 * 
	 * 			- 일반 게시판 등록 화면
	 * 				> 접근 제한에 걸려 스프링 시큐리티가 기본적으로 제공하는 로그인 페이지가 연결되고,
	 * 				일반회원 등급인 ROLE_MEMBER 권한을 가진 member 계정으로 로그인 후 해당 페이지로 접근
	 * 				가능합니다.
	 * 				> 관리자 등급인 admin 계정은 ROLE_MEMBER 권한도 가지고 있는 계정이므로
	 * 				해당 페이지로 접근 가능합니다.
	 * 			- 공지사항 게시판 등록 화면
	 * 				> 접근 제한에 걸려 스프링 시큐리티가 기본적으로 제공하는 로그인 페이지가 연결되고,
	 * 				관리자 등급인 ROLE_ADMIN 권한을 가진 admin 계정으로 로그인 후 해당 페이지로 접근 가능 
	 * 	
	 *  5. 접근 거부 처리
	 *  - 접근 거부가 발생한 상황을 처리하는 접근 거부 처리자의 URI를 지정할 수 있다.
	 *  
	 *  	# 환경 설정
	 *  		
	 *  		- 스프링 웹 설정(servlet-context.xml 설정)
	 *  			> <context:component-scan base-package="kr.or.ddit.security" />
	 *  		
	 *  		- 스프링 시큐리티 설정(security-context.xml 설정)
	 *  			> 접근 거부 처리자의 URI를 지정
	 *  			> <security:access-denied-handler error-page="/accessError" />
	 * 			
	 * 		# 접근 거부 처리
	 * 			
	 * 			- 접근 거부 처리 컨트롤러 작성
	 * 				> security.CommonController
	 * 
	 * 		# 화면 설명
	 * 
	 * 			- 일반 게시판 등록 페이지
	 * 				> 접근 제한에 걸려 스프링 시큐리티가 제공하는 로그인 페이지가 나타나고,
	 * 					회원 권한을 가진 계정으로 접근 시 접근 가능
	 * 
	 * 			- 공지사항 게시판 등록 페이지
	 * 				> 접근 제한에 걸려 스프링 시큐리티가 제공하는 로그인 페이지가 나타나고,
	 * 					회원 권한을 가진 계정으로 접근 시에 공지사항 게시판 등록 페이지는 
	 * 					관리자 권한으로만 접근 가능하므로 접근이 거부됩니다.
	 * 					이때, access-denied-handler로 설정되어 있는 URI로 이동하고
	 * 					해당 페이지에서 접근이 거부되었을 때 보여질 페이지의 정보가 나타난다.
	 * 
	 * 	6. 사용자 정의 접근 거부 처리자
	 * 	- 접근 거부가 발생한 상황에 단순 메세지 처리 이상의 다양한 처리를 하고 싶다면 AccessDeniedHandler를
	 * 		직접 구현해야한다.
	 * 
	 * 		# 환경 설정
	 * 		
	 * 			- 스프링 시큐리티 설정(security-context.xml 설정)
	 * 				> id가 'customAccessDenied'를 가진 빈을 등록한다.
	 * 				> <security:access-denied-handler ref="customAccessDenied" />
	 * 		
	 * 		# 접근 거부 처리자 클래스 정의
	 * 			
	 * 			- 사용자가 정의한 접근 거부 처리자
	 * 				> CustomAccessDeniedHandler 클래스 정의
	 * 				- AccessDeniedHandler 인터페이스를 참조받아서 handle 메소드를 재정의하여 사용
	 * 				: 우리는 접근이 거부되었을 때 빈으로 등록해둔 CustomAccessDeniedHandler 클래스가
	 * 				발동해 해당 메소드가 실행되고 response 내장 객체를 활용하여 /accessError URL로
	 * 				이동하여 접근 거부시 보여질 페이지로 이동하지만 이곳에서 더 많은 로직을 처리하길 원한다면
	 * 				request, response 내장 객체를 이용하여 다양한 처리가 가능하다.
	 * 	
	 * 		# 화면 설명
	 * 			
	 * 			- 일반 게시판 등록 페이지
	 * 				> 접근 제한에 걸려 스프링 시큐리티가 제공하는 로그인 페이지가 나타나고,
	 * 					회원 권한을 가진 계정으로 접근 시 접근 가능
	 * 			- 공지사항 게시판 등록 페이지
	 * 				> 접근 제한에 걸려 스프링 시큐리티가 제공하는 로그인 페이지가 나타나고, 회원 권한을 가진
     *           	계정으로 접근 시에 공지사항 게시판 등록 페이지는 관리자 권한만 접근 가능하므로 접근이 거부된다.
     *           	이때, access-denied-handler로 설정되어 있는 ref 속성에 부여된 클래스 메소드로
     *           	이동하고 해당 페이지에서 접근이 거부되었을 때 페이지의 정보가 나타난다.
     *           
     *	7. 사용자 정의 로그인 페이지
     *	- 기본 로그인 페이지가 아닌 사용자가 직접 정의한 로그인 페이지를 사용한다.
     *
     *		# 환경 설정
     *			
     *			- 스프링 시큐리티 설정(security-context.xml 설정)
     *			> <security:form-login/> 삭제 (기본 로그인 페이지로 사용하는게 아니기 때문에 주석)
     *			> <security:form-login login-page="/login"/> 설정
     *			: 사용자가 직접 만든 로그인 페이지로 이용할 /login URL을 가지고 있는 컨트롤러 메소드를 정의
     *
     *		# 로그인 페이지 정의
     *
     *			- 사용자가 정의한 로그인 컨트롤러
     *				> controller 패키지 안에 LoginController 메소드 생성
     *			- 사용자가 정의한 로그인 뷰
     *				> security/loginForm.jsp
     *			
     *			** 시큐리티에서 제공하는 기본 로그인 페이지로 이동하지 않고,
     *				사용자가 정의한 로그인 페이지의 URI를 요청하여 해당 페이지에서 권한을 체크하도록 합니다.
     *				인증이 완료되면 최초의 요청된 target URI로 이동합니다.
     *				그렇지 않은 경우 사용자가 만들어놓은 접근 거부 페이지로 이동합니다.
     *	
     *	8. 로그인 성공 처리
     *	- 로그인을 성공한 후에 로그인 이력 로그를 기록하는 등의 동작을 하고 싶은 경우가 있다.
     *		이런 경우에 AuthenticationSuccessHandler라는 인터페이스를 구현해서 로그인 성공 처리자로
     *		지정할 수 있다.
     *
     *		# 환경 설정
     *	
     *			- 스프링 시큐리티 설정(security-context.xml 설정)
     *			> customLoginSuccess bean 등록
     *			> <security:form-login login-page="/login" 
     *				authentication-success-handler-ref="customLoginSuccess"/> 추가
     *
     *		# 로그인 성공 처리자 클래스 정의
     *			
     *			- 로그인 성공 처리자
     *			> SavedRequestAwareAuthenticationSuccessHandler는
     *				AuthenticationSuccessHandler의 구현 클래스입니다.
     *				인증 전에 접근을 시도한 URL로 리다이렉트하는 기능을 가지고 있으며
     *				스프링 시큐리티에서 기본적으로 사용되는 구현 클래스입니다.
     *			- 로그인 성공 처리자2
     *			> AuthenticationSuccessHandler 인터페이스를 직접 구현하여
     *				인증 전에 접근을 시도한 URL로 리다이렉트하는 기능을 구현한다.
     *
     *		# 화면 설명
     *		
     *			- 일반 게시판 등록 화면
     *				> 사용자가 정의한 로그인 페이지에서 회원 권한에 해당하는 계정으로 로그인 시,
     *				성공했다면 성공 처리자인 CustomLoginSuccess 클래스로 넘어가
     *				넘겨받은 파라미터들 중 authentication 안에 principal로 User 정보를 받아서
     *				username과 password를 출력합니다. (출력 정보는 로그인 성공 시 인증된 회원 정보)
	 * 				
	 *  9. 로그아웃 처리
	 *  - 로그아웃을 위한 URI를 지정하고, 로그아웃 처리 후에 별도의 작업을 하기 위해서 사용자가 직접 구현한
	 *  처리자를 등록할 수 있다.
	 *  
	 *  	# 환경 설정
	 *  
	 *  		- 스프링 시큐리티 설정(security-context.xml 설정)
	 *  		> <security:logout logout-url="/logout" invalidate-session="true"/>
	 *  		
	 *  		** logout 경로는 스프링에서 제공하는 /logout 경로를 설정한다. (default)
	 *  			
	 *  
	 *  
	 *  
	 *  
	 *  
	 */
}
















