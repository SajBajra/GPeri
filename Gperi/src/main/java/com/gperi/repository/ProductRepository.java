package com.gperi.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import com.gperi.model.Product;

public interface ProductRepository extends JpaRepository<Product, Long> {
	List<Product> findAllByCategory_Id(int id);
}
