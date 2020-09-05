package telran.ashkelon2020.accounting.security.service;

import java.time.LocalDateTime;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import telran.ashkelon2020.accounting.dao.UserAccountRepository;
import telran.ashkelon2020.accounting.model.UserAccount;
import telran.ashkelon2020.forum.dao.PostRepository;
import telran.ashkelon2020.forum.model.Post;

@Service("customSecurity")
public class CustomWebSecurityService {

	@Autowired
	PostRepository postRepository;
	
	@Autowired
	UserAccountRepository userAccountRepository;

	public boolean checkPostAuthority(String id, String user) {
		Post post = postRepository.findById(id).orElse(null);
		return post==null ? true : post.getAuthor().equals(user);
	}
	
	public boolean checkUserExpDate(String user) {
		UserAccount userAccount = userAccountRepository.findById(user).orElse(null);
		return userAccount.getExpDate().isAfter(LocalDateTime.now());
	}
	
	public boolean notBanned(String user) {
		UserAccount userAccount = userAccountRepository.findById(user).orElse(null);
		return userAccount.getRoles().isEmpty() ? false : true;
	}
	
	public boolean checkAuthorOrModerator(String user, String postId) {
		UserAccount userAccount = userAccountRepository.findById(user).orElse(null);
		Post post = postRepository.findById(postId).orElse(null);
		return post.getAuthor().equals(user) || userAccount.getRoles().contains("MODERATOR");
	}
	
	public boolean checkAuthor(String user, String postId){
		Post post = postRepository.findById(postId).orElse(null);
		return post.getAuthor().equals(user);
	}
}
