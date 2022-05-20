package com.lcomputerstudy.example.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.lcomputerstudy.example.domain.Category;
import com.lcomputerstudy.example.mapper.CategoryMapper;

@Service
public class CategoryServiceImpl implements CategoryService {

	@Autowired
	CategoryMapper categoryMapper;
	
	@Override
	public List<Category> getCategories() {
		// TODO Auto-generated method stub
		return categoryMapper.getCategories();
	}

	@Override
	public void insertCategory(Category category) {
		categoryMapper.insertCategory(category);
		
	}

	@Override
	public void insertchildCategory(Category category) {
		categoryMapper.insertchildCategory(category);
		categoryMapper.insertchildCategory2(category);
		
	}

	@Override
	public void editCategory(Category category) {
		categoryMapper.editCategory(category);
		
	}

	@Override
	public void deleteCategory(int code) {
		categoryMapper.deleteCategory(code);
		
	}

	@Override
	public List<Category> getMenu() {
		// TODO Auto-generated method stub
		return categoryMapper.getMenu();
	}

	@Override
	public List<Integer> getCodes(int code) {
		// TODO Auto-generated method stub
		return categoryMapper.getCodes(code);
	}

}
