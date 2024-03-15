package kr.or.ddit.controller;

import java.security.Principal;
import java.util.Iterator;

import javax.annotation.PostConstruct;
import javax.inject.Inject;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import kr.or.ddit.vo.CustomUser;

@Controller
@RequestMapping("/board")
public class BoardController {
	
	private static final Logger log = LoggerFactory.getLogger(BoardController.class);
	
	@Inject
	private PasswordEncoder pe;
	
	@PostConstruct
	public void init() {
		System.out.println("######## "+pe.encode("1234"));
		System.out.println("######## "+pe.encode("1234"));
		System.out.println("######## "+pe.encode("1234"));
		System.out.println("######## "+pe.encode("1234"));
		System.out.println("######## "+pe.encode("1234"));
		System.out.println("######## "+pe.encode("1234"));
		System.out.println("######## "+pe.encode("1234"));
		System.out.println("######## "+pe.encode("1234"));
	}
	
	@RequestMapping(value="/list", method=RequestMethod.GET)
	public String list() {
		return "board/list";
	}
	
	@PreAuthorize("hasAnyRole('ROLE_MEMBER', 'ROLE_ADMIN')")
	@RequestMapping(value="/register", method=RequestMethod.GET)
	public String registerForm(Principal principal) {
		
		//사용자 정보 가져오기
		//방법 1 (Principal 객체를 받아와서 사용 - getName만 가져오는.. 제한적임)
		log.info("principal.getName() : " + principal.getName());
		
		
		//방법2 User 객체 정보 얻어오기
		User user = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
		
		log.info("user.getUsername() : " + user.getUsername());
		log.info("user.getPassword() : " + user.getPassword());
		
		//역할명 얻어오기
		Iterator<GrantedAuthority> ite = user.getAuthorities().iterator();
		while(ite.hasNext()) {
			log.info("권한 : " + ite.next().getAuthority());
		}

		CustomUser customUser = (CustomUser) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
		log.info("내가 조회한 내 정보(아이디) : " + customUser.getMember().getUserId());
		log.info("내가 조회한 내 정보(이름) : " + customUser.getMember().getUserName());
		
		
		return "board/register";
	}
}
