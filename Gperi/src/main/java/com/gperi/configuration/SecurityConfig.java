package com.gperi.configuration;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.gperi.service.CustomUserDetailService;


@Configuration
@EnableWebSecurity
public class SecurityConfig {
	@Autowired
	GoogleOAuth2SucessHandler googleOAuth2SucessHandler;
	
	@Autowired
	CustomUserDetailService customUserDetailService;
	
	@Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }
	
	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/", "/shop/**", "/forgotPasswordPage", "/register", "/forgotPassword" ,"/verifyOTP", "/resetPassword").permitAll()
                        .requestMatchers("/admin/**").hasRole("ADMIN")
                        .anyRequest()
                        .authenticated())
                .formLogin(login -> login
                        .loginPage("/login")
                        .permitAll()
                        .failureUrl("/login?error=true")
                        .defaultSuccessUrl("/")
                        .usernameParameter("email")//for login check however u know
                        .passwordParameter("password"))
                .oauth2Login(login -> login
                        .loginPage("/login")// page yo vanera dekhako
                        .successHandler(googleOAuth2SucessHandler))
                .logout(logout -> logout
                        .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                        .logoutSuccessUrl("/login")// logout garesi feri login ma janxa
                        .invalidateHttpSession(true) //session finish vayo
                        .deleteCookies("JSESSIONID"))
                
                
                .csrf(csrf -> csrf
                        .disable());
        
		http.authenticationProvider(daoauthenticationProvider());
		return http.build();
	}
	

	    @Bean
	    public WebSecurityCustomizer webSecurityCustomizer() {
	        return (web) -> web.ignoring().requestMatchers("/resources/**","/static/**", "/images/**", "/productImages/**", "/css/**", "/js/**", "/assets/**","/public/**", "/img/**");
	    }

	    
	    
	    @Bean
	    public DaoAuthenticationProvider daoauthenticationProvider() {
	    	DaoAuthenticationProvider provider= new DaoAuthenticationProvider();
	    	provider.setUserDetailsService(this.customUserDetailService);
	    	provider.setPasswordEncoder(bCryptPasswordEncoder());
	    	return provider;
	    }
	    
	  
	    
	}
	


