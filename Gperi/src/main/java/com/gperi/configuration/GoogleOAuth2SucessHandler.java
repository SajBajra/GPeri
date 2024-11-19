package com.gperi.configuration;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import com.gperi.model.Role;
import com.gperi.model.User;
import com.gperi.repository.RoleRepository;
import com.gperi.repository.UserRepository;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;


@Component
public class GoogleOAuth2SucessHandler implements AuthenticationSuccessHandler {


	@Autowired
	RoleRepository roleRepository;
	@Autowired
	UserRepository userRepository;
	
	private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy(); //internal redirect easily garna milxa 
	public void onAuthenticationSuccess(HttpServletRequest httpServletrequest, HttpServletResponse httpServletresponse,
			Authentication authentication) throws IOException, ServletException { //gets token from authentication 
		
		OAuth2AuthenticationToken token = (OAuth2AuthenticationToken) authentication; //token linxa
		String email = token.getPrincipal().getAttributes().get("email").toString(); //token leara check garxa so eta token bata email linxa
		//principal le logged in user bata data linxa
		
		if(userRepository.findUserByEmail(email).isPresent()) {
			//khali xodeko bc kei garnu nai padhdaina xD
			
		}else {
			User user = new User(); //token bata info nikaera haldae jane
			user.setFirstName(token.getPrincipal().getAttributes().get("given_name").toString()); 
			user.setLastName(token.getPrincipal().getAttributes().get("family_name").toString());
			user.setEmail(email);
			List<Role> roles = new ArrayList<>(); //aba role garne for user 
			roles.add(roleRepository.findById(2).get()); // yo chahi always 2 bc its for user and admin ko nagarnu karan admin ko direct push haneko db ma xD
			//roles halna birsera error aako xD
			// findbyid(2) is providing null data, first populate database with required datas
			user.setRoles(roles);
			userRepository.save(user);//new user save gareko easy xD
			
		}
		
		redirectStrategy.sendRedirect(httpServletrequest, httpServletresponse, "/"); //simply redirected from internal instead of doing it from return 

	}
	
	
}
