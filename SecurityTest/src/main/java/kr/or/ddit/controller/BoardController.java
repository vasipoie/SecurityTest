package kr.or.ddit.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/board")
public class BoardController {
	
	@RequestMapping(value="/list")
	public String list() {
		return "board/list";
	}
	
	@RequestMapping(value="/register")
	public String registerForm() {
		return "board/register";
	}
}
