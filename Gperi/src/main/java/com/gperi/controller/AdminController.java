package com.gperi.controller;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

import com.gperi.dto.ProductDTO;
import com.gperi.model.Category;
import com.gperi.model.Product;
import com.gperi.service.CategoryService;
import com.gperi.service.ContactService;
import com.gperi.service.ProductService;
import com.gperi.service.UserService;


@Controller
public class AdminController {
	
	public static String uploadDir = System.getProperty("user.dir") + "/src/main/resources/static/productImages";

	@Autowired
	CategoryService categoryService;
	@Autowired
	ProductService productService;
	@Autowired
	ContactService contactService;
	@Autowired
	UserService userService;
	
	@GetMapping("/admin")
	public String admin(Model model) {
		return "adash";
	}

	 
	@GetMapping("/admin/auser")
	public String getAllUsers(Model model) {
        model.addAttribute("users", userService.getAllUser());
        return "auser"; 
    }
	@GetMapping("/admin/acontact")
	public String getAllContact(Model model) {
		model.addAttribute("contacts", contactService.getAllContact());
        return "acontact"; 
    }
	
	@GetMapping("/admin/categories")
	public String getCat(Model model) {
		model.addAttribute("categories", categoryService.getAllCategory());
		return "categories";
	}
	
	@GetMapping("/admin/categories/add")
	public String getCatAdd(Model model) {
		model.addAttribute("category", new Category());
	 return "categoriesAdd";
	}
	@PostMapping("/admin/categories/add")
	public String postCatAdd(@ModelAttribute("category") Category category) {
		categoryService.addCategory(category);
		return "redirect:/admin/categories";
	}
	@GetMapping("admin/categories/delete/{id}")
	public String deleteCat(@PathVariable int id) {
		categoryService.removeCategoyById(id);
		return "redirect:/admin/categories";
	}
	@GetMapping("/admin/categories/update/{id}")
	public String updateCat(@PathVariable int id, Model model) {
		Optional<Category> category = categoryService.getCategoryById(id); /* value huna ni sakxa na huna ni sakxa */
		if(category.isPresent()) {
			model.addAttribute("category",category.get());
			return "categoriesAdd";
		}else
			return "404";
	}
	
	
	@GetMapping("/admin/products")
	public String products(Model model) {
		model.addAttribute("products", productService.getAllProduct());
		return "products";
	}
	@GetMapping("/admin/products/add")
	public String productAddGet(Model model) {
		model.addAttribute("productDTO", new ProductDTO());
		model.addAttribute("categories", categoryService.getAllCategory());
		return "productsAdd";
	}
	
	
	

	@PostMapping("/admin/products/add")
	public String productAddPost(@ModelAttribute("productDTO") ProductDTO productDTO, 
			@RequestParam("productImage") MultipartFile file,
			@RequestParam("imgName") String imgName)throws IOException{
		Product product = new Product();
		product.setId(productDTO.getId());
		product.setName(productDTO.getName());
		product.setCategory(categoryService.getCategoryById(productDTO.getCategoryId()).get());
		product.setPrice(productDTO.getPrice());
		product.setDescription(productDTO.getDescription());
		String imageUUID;    /*uuid 128bit number for image*/
		if(!file.isEmpty()) {
			imageUUID =file.getOriginalFilename();
			Path fileNameAndPath =Paths.get(uploadDir, imageUUID);
			Files.write(fileNameAndPath, file.getBytes()); /* save to path */
			
		
		}else {
			imageUUID =imgName;
		}
		product.setImageName(imageUUID);
		productService.addProduct(product);
		
		
		return "redirect:/admin/products";
	}
	
	
	
	@GetMapping("/admin/product/delete/{id}")
	public String deleteProduct(@PathVariable long id) {
		productService.removeProductById(id);
		return "redirect:/admin/products";
	}
	
	@GetMapping("/admin/product/update/{id}")
	public String updateProductGet(@PathVariable long id, Model model) {
		Product product= productService.getProductById(id).get();
		ProductDTO productDTO = new ProductDTO();
		productDTO.setId(product.getId());
		productDTO.setName(product.getName());
		productDTO.setCategoryId(product.getCategory().getId());
		productDTO.setPrice(product.getPrice());
			productDTO.setDescription(product.getDescription());
		productDTO.setImageName(product.getImageName());
		
		model.addAttribute("categories", categoryService.getAllCategory());
		model.addAttribute("productDTO", productDTO);
		return "productsAdd";
	}
}
