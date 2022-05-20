package com.lcomputerstudy.example.service;

import java.util.List;

import com.lcomputerstudy.example.domain.Option;
import com.lcomputerstudy.example.domain.Product;

public interface ProductService {

	void createProduct(Product product);

	void insertOptions(Option option, int code);

	void insertfilesname(String filesname, String code);

	List<Product> getProductList();

	void insertMainPhoto(String string, String code);

	void deleteProduct(int code);

	Product getProductDetails(int code);

	List<Option> getOptions(int code);

	void editProduct(Product product);

	void editOptions(Option option, int num);

	List<Product> getproductlist_shop(int code);

	void updateProductStock(int p_code, int count);

	void updateRating(Product p);

	List<Product> getRankingList();

}
