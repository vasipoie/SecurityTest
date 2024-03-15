<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ taglib uri="http://www.springframework.org/security/tags" prefix="sec" %>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Insert title here</title>
</head>
<body>
	<h3>BOARD REGISTER : access to member</h3>
	
	<hr/>
	
	<sec:authentication property="principal" var="principal"/>
	<sec:authentication property="principal.member" var="member"/>
	<sec:authentication property="principal.member.userId" var="id"/>
	<sec:authentication property="principal.member.userPw" var="pw"/>
	<sec:authentication property="principal.member.userName" var="name"/>
	
	<p>principal : ${principal }</p>
	<p>
		사용자 아이디 : ${id }<br/>
		사용자 비밀번호 : ${pw }<br/>
		사용자 이름 : ${name }<br/>
	</p>
	
	<hr/>
	<p>
		<sec:authorize access="hasRole('ROLE_MEMBER')">
			역할명은 회원이지요~ <br/>
		</sec:authorize>
		<sec:authorize access="hasRole('ROLE_ADMIN')">
			역할명은 관리자이지요~ <br/>
		</sec:authorize>
	</p>
	
	<a href="/">HOME</a>
</body>
</html>