package kr.or.ddit.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;


@Controller
public class CommonController {
	
	Logger log = LoggerFactory.getLogger(CommonController.class);

	@RequestMapping(value="/accessError", method=RequestMethod.GET)
	public String accessDenied(Authentication auth, Model model) {
		
		log.info("accessDenied() 실행...!");
		log.info("accessDenied : " + auth);
		
		// org.springframework.security.authentication.UsernamePasswordAuthenticationToken@34234
		// Principal : org.springframework.security.core.userdetails.User@ahfh784
		// Username : member;
		// Password : [PROTECTED];
		// Enabled : true;
		// AccountNonExpired : true;
		// credentialsNonExpired : true;
		// AccountNonLocked : true;
		// Granted Authorities : ROLE_MEMBER;
		// Credentials : [PROTECTED];
		// Authenticated : true;
		// Details : org.springframework.security.web.authentication.WebAuthenticationDetail@166c822
		// SessionId : B8u8897y89y87OKLHKU**U**U*KJH;
		// Granted Authorities : ROLE_MEMBER
		
		model.addAttribute("msg", "Access Denied");
		return "accessError";
	}
}
