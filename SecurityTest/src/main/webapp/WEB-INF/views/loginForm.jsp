<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ taglib uri="http://www.springframework.org/security/tags" prefix="sec" %>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Insert title here</title>
</head>
<body>
	<h1>여기는 LOGIN</h1>
	<h2>에러정보가 있다면? ${error }</h2> <!-- 에러 발생 시, 출력할 메세지 -->
	<h2>로그아웃~ 빠잉 ${logout }</h2>	 <!-- 로그아웃 시, 출력할 메세지 -->
	
	<!-- name을 시큐리티에서 정해진 규칙대로 작성해야한다 -->
	<form method="post" action="/login">
		username : <input type="text" name="username"/><br/>
		password : <input type="text" name="password"/><br/>
		<input type="checkbox" name="remember-me"/> Remember Me
		<input type="submit" value="로그인"/>
		<!-- sec:csrfInput = csrf토큰을 가져다주는 역할 -->
		<sec:csrfInput/>
	</form>
	
	
</body>
</html>