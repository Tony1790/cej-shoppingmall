package com.lcomputerstudy.example.response;

import java.util.List;

import com.lcomputerstudy.example.domain.Product;

public class WishListResponse {
	
	private List<Integer> wishItems;
	private List<Product> products;
	
	public WishListResponse(List<Integer> wishItems, List<Product> products) {
		this.wishItems = wishItems;
		this.products = products;
		
	}

	public List<Integer> getWishItems() {
		return wishItems;
	}

	public void setWishItems(List<Integer> wishItems) {
		this.wishItems = wishItems;
	}

	public List<Product> getProducts() {
		return products;
	}

	public void setProducts(List<Product> products) {
		this.products = products;
	}
	
	

}
