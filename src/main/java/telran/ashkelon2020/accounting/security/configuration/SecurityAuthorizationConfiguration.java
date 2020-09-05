package telran.ashkelon2020.accounting.security.configuration;

import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

//@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true) // позволяет применять аннотацию @PreAuthorized (в контроллере) 
public class SecurityAuthorizationConfiguration extends WebSecurityConfigurerAdapter {
	
	@Override
	public void configure(WebSecurity web) {
		web.ignoring().antMatchers("/account/register");
	}
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.httpBasic();
		http.csrf().disable();
		http.authorizeRequests()
			.antMatchers(HttpMethod.GET).permitAll()
			.antMatchers(HttpMethod.POST, "/forum/posts/**").permitAll()
			.antMatchers("/account/user/{login}/role/{role}**")
			.hasRole("ADMINISTRATOR")
			.antMatchers(HttpMethod.POST, "/account/login**")
				.access("@customSecurity.checkUserExpDate(authentication.name) "
						+ "and @customSecurity.notBanned(authentication.name)")
				
			.antMatchers(HttpMethod.POST, "/forum/post/{author}**").access("#author==authentication.name"
					+ " and @customSecurity.notBanned(#author) and @customSecurity.checkUserExpDate(#author)")
			
			.antMatchers(HttpMethod.PUT, "/account/user/{login}**").access("#login==authentication.name and"
					+ "@customSecurity.checkUserExpDate(#login) and @customSecurity.notBanned(#login)")
			
			.antMatchers(HttpMethod.DELETE, "/account/user/{login}**").access("#login==authentication.name")
			
			.antMatchers(HttpMethod.DELETE, "/forum/post/{id}**")
				.access("@customSecurity.checkAuthorOrModerator(authentication.name, #id) and "
						+ "@customSecurity.notBanned(authentication.name) and "
						+ "@customSecurity.checkUserExpDate(authentication.name)")
			
			.antMatchers(HttpMethod.PUT, "/forum/post/{id}**")
				.access("@customSecurity.checkAuthorOrModerator(authentication.name) and "
						+ "@customSecurity.notBanned(authentication.name) and "
						+ "@customSecurity.checkUserExpDate(authentication.name)")
			
			.antMatchers(HttpMethod.PUT, "/forum/post/{id}/like**").access("@customSecurity.checkUserExpDate(authentication.name) "
					+ "and @customSecurity.notBanned(authentication.name)")
			
			.antMatchers(HttpMethod.PUT, "/forum/post/{id}/comment/{author}**").access("@customSecurity.checkUserExpDate(#author) "
					+ "and @customSecurity.notBanned(#author) and #author==authentication.name")
			
			.antMatchers(HttpMethod.PUT,"/forum/post/{id}**")
			.access("@customSecurity.checkPostAuthority(#id, authentication.name) or hasRole('MODERATOR')")
			
			.antMatchers(HttpMethod.POST, "/account/password**").authenticated();
	}

}
