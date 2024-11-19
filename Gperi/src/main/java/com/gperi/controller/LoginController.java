package com.gperi.controller;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.gperi.global.GlobalData;
import com.gperi.model.Role;
import com.gperi.model.User;
import com.gperi.repository.RoleRepository;
import com.gperi.repository.UserRepository;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

@Controller
public class LoginController {
	
	@Autowired
	private BCryptPasswordEncoder bCryptPasswordEncoder;
	@Autowired
	UserRepository userRepository;
	@Autowired
	RoleRepository roleRepository;
	
	 @Autowired
	    private JavaMailSender emailSender;
	
	 private Map<String, String> otpMap = new HashMap<>();

	
	@GetMapping("/login")
	public String login() {
		
		GlobalData.cart.clear();
		return "login";
	}
	
	@GetMapping("/register")
	public String registerGet() {
		return "register";
	}
	
	@PostMapping("/register")
	public String registerPost(@ModelAttribute("user")User user, HttpServletRequest request) throws ServletException{
		String password =user.getPassword();
		user.setPassword(bCryptPasswordEncoder.encode(password));
		List<Role> roles = new ArrayList<>();
		roles.add(roleRepository.findById(2).get());
		user.setRoles(roles);
		userRepository.save(user);// Spring Security typically handles creating and managing user sessions automatically upon successful login
		request.login(user.getEmail(), password);
		return "redirect:/";
	}

	
	
	
	
	
	
    @GetMapping("/forgotPasswordPage")
    public String forgotPasswordPage() {
        return "forgotPassword.html";
    }

    @PostMapping("/forgotPassword")
    public String forgotPassword(@RequestParam("email") String email, Model model) {
        User user = userRepository.findByEmail(email);
        if (user == null) {
            model.addAttribute("invalidEmail", true);
            return "forgotPassword.html"; // Stay on the forgot password page
        }

        String otp = generateOTP();
        System.out.println("Generated OTP for email " + email + ": " + otp);
        otpMap.put(email, otp); // Store the OTP in the map with the email as the key
        sendOTPEmail(email, otp);
        
        model.addAttribute("email", email);
        // Redirect to the verifyOTP page with the email parameter
       return "verifyOTP.html";
    }


    private String generateOTP() {
        // Generate a 6-digit OTP
        Random random = new Random();
        int otp = 100000 + random.nextInt(900000);
        return String.valueOf(otp);
    }

    private void sendOTPEmail(String email, String otp) {
        // Get current timestamp
        long timestamp = System.currentTimeMillis();
        // Combine OTP value and timestamp into a single string separated by ':'
        String otpWithTimestamp = otp + ":" + timestamp;
        MimeMessage message = emailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message);
        try {
            helper.setTo(email);
            helper.setSubject("Password Reset OTP");
            helper.setText("Your OTP for password reset is: " + otp+"\n\nYour OTP will expire in 5 minutes.");
        } catch (MessagingException e) {
            e.printStackTrace();
        }
        emailSender.send(message);
        // Store OTP with timestamp in the map
        otpMap.put(email, otpWithTimestamp);
    }


    @PostMapping("/verifyOTP")
    public String verifyOTP(@RequestParam("email") String email, @RequestParam("otp") String otp, Model model) {
        String storedOTP = otpMap.get(email); // Retrieve the OTP using the email as the key
        System.out.println("Email received in verifyOTP: " + email);
        System.out.println("OTP received in verifyOTP: " + otp);
        System.out.println("Retrieved OTP for email " + email + ": " + storedOTP);
        if (storedOTP != null) {
            // Split the storedOTP to extract OTP value and timestamp
            String[] storedOTPParts = storedOTP.split(":");
            String otpValue = storedOTPParts[0];
            long otpTimestamp = Long.parseLong(storedOTPParts[1]);
            long currentTimestamp = System.currentTimeMillis();

            // Check if OTP is expired (10 minutes)
            if (currentTimestamp - otpTimestamp > 300000) {
                // OTP is expired
                model.addAttribute("expiredOTP", true);
                return "forgotPassword.html";
            }

            if (otpValue.equals(otp)) {
            	model.addAttribute("email", email);
                // OTP is valid, allow the user to reset password
                return "resetPassword.html";
            } else {
                // OTP is invalid
                model.addAttribute("invalidOTP", true);
                return "forgotPassword.html";
            }
        } else {
            // No OTP found for the email
            model.addAttribute("invalidOTP", true);
            return "forgotPassword.html";
        }
    }

    
    @PostMapping("/resetPassword")
    public String resetPassword(@RequestParam("email") String email, @RequestParam("password") String password, Model model) {
       
        User user = userRepository.findByEmail(email);
        System.out.println(email);
        System.out.println(user);
        // Hash the new password
        String hashedPassword = BCrypt.hashpw(password, BCrypt.gensalt());
        user.setPassword(hashedPassword);
        userRepository.save(user);

        // Clear OTP from map after password reset
        otpMap.remove(email);

        model.addAttribute("passwordResetSuccess", true);
        return "login.html"; // Redirect to login page after password reset
    }
}
