package com.lcomputerstudy.example.service;

import java.util.List;

import com.lcomputerstudy.example.domain.Category;

public interface CategoryService {

	List<Category> getCategories();

	void insertCategory(Category category);

	void insertchildCategory(Category category);

	void editCategory(Category category);

	void deleteCategory(int code);

	List<Category> getMenu();

	List<Integer> getCodes(int code);

}
