package com.gperi.global;

import java.util.ArrayList;
import java.util.List;

import com.gperi.model.Product;

public class GlobalData {
 public static List<Product> cart; //static in nature 
 	static {
	 cart= new ArrayList<Product>();
 			}
}
