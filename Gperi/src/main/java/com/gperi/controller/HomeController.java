package com.gperi.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;

import com.gperi.global.GlobalData;
import com.gperi.model.Contact;
import com.gperi.model.User;
import com.gperi.repository.UserRepository;
import com.gperi.service.CategoryService;
import com.gperi.service.ContactService;
import com.gperi.service.ProductService;

@Controller
public class HomeController {
	@Autowired
	CategoryService categoryService;
	@Autowired
	ProductService productService;
	@Autowired
	ContactService contactService;
	
	@GetMapping({"/","/home"})
	public String home(Model model) {
		model.addAttribute("cartCount", GlobalData.cart.size());
		return "index";
	}
	@GetMapping("/404")
	public String ErrorPage() {
		return "404.html";
	}
	@GetMapping("/error")
	public String ErrorPage2() {
		return "error.html";
	}
	@PostMapping("/submitContact")
    public String submitContactForm(@ModelAttribute Contact contact) {
        contactService.saveContact(contact);
        return "redirect:/"; 
    }
	
	@GetMapping("/contact")
	public String contact(Model model) {
		model.addAttribute("cartCount", GlobalData.cart.size());	
		return "contact";
	}
	@GetMapping("/about")
	public String about(Model model) {
		model.addAttribute("cartCount", GlobalData.cart.size());	
		return "about";
	}
	
	@GetMapping("/shop")
	public String shop(Model model) {
		model.addAttribute("cartCount", GlobalData.cart.size());	
		model.addAttribute("categories", categoryService.getAllCategory());
		model.addAttribute("products", productService.getAllProduct());
		return "shop";
	}
	
	@GetMapping("/shop/category/{id}")
	public String shopByCategory(Model model, @PathVariable int id) {
		model.addAttribute("cartCount", GlobalData.cart.size());	
		model.addAttribute("categories", categoryService.getAllCategory());
		model.addAttribute("products", productService.getAllProductsByCategoryId(id));
		return "shop";
	}
	
	
	@GetMapping("/shop/viewproduct/{id}")
	public String viewProduct(Model model, @PathVariable int id) {
		model.addAttribute("cartCount", GlobalData.cart.size());
		model.addAttribute("product",productService.getProductById(id).get());
		return "viewProduct";
	}
	
	
	
	
}
