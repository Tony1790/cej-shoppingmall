package com.lcomputerstudy.example.mapper;

import java.util.List;

import org.apache.ibatis.annotations.Mapper;

import com.lcomputerstudy.example.domain.Category;

@Mapper
public interface CategoryMapper {

	List<Category> getCategories();

	void insertCategory(Category category);

	void insertchildCategory(Category category);

	void insertchildCategory2(Category category);

	void editCategory(Category category);

	void deleteCategory(int code);

	List<Category> getMenu();

	List<Integer> getCodes(int code);
}
