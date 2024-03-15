package kr.or.ddit.mapper;

import kr.or.ddit.vo.MemberVO;

public interface IMemberMapper {

	public MemberVO readByUserId(String username);

}
