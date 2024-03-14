<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Insert title here</title>
</head>
<body>
	<h3>h3태그 Access Denied</h3>
	
	<!-- 
		SPRING_SECURITY_403_EXCEPTION는 'Access is denied' 문자열이 출력됩니다.
		security-context.xml에서 security:access-denied-handler 태그 자체로 설정했을 때
		메세지가 출력됩니다.
	 -->
	<h2>${SPRING_SECURITY_403_EXCEPTION.message }</h2>
	<h2>${msg }</h2>
</body>
</html>