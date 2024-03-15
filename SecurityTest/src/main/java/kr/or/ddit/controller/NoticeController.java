package kr.or.ddit.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/notice")
public class NoticeController {

	@GetMapping(value="/list")
	public String list() {
		return "notice/list";
	}
	
	@PreAuthorize("hasRole('ROLE_ADMIN')")
	@GetMapping(value="/register")
	public String registerForm() {
		return "notice/register";
	}
}
