package com.gperi.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.gperi.model.Category;


public interface CategoryRepository extends JpaRepository <Category, Integer> {

}