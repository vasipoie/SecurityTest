package kr.or.ddit.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

@Controller
public class LoginController {

	private static final Logger log = LoggerFactory.getLogger(LoginController.class);
	
	@RequestMapping(value="/login", method=RequestMethod.GET)
	public String loginForm(String error, String logout, Model model) {
		
		log.info("error : " + error);
		log.info("logout : " + logout);
		
		if(error != null) {
			model.addAttribute("error", "에러났슈");
		}
		if(logout != null) {
			model.addAttribute("logout", "로그아웃!");
		}
		
		return "loginForm";
	}
	
	@RequestMapping(value="/logout", method=RequestMethod.GET)
	public String logoutForm() {
		return "logoutForm";
	}
	
}
