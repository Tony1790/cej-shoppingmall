package com.lcomputerstudy.example.domain;

import java.util.List;

import org.springframework.web.multipart.MultipartFile;

public class Product {

	private int code;
	private String category;
	private String name;
	private String descr;
	private List<String> type;
	private boolean isSale;
	private String detail_desc;
	private String material;
	private String size;
	private String manufacturer;
	private String caution;
	private int price;
	private String point;
	private int stock;
	private String shipping;
	private List<Option> options;
	private String type_s;
	private String filesname;
	private String mainPhoto;
	private String mainCategory;
	private List<String> file_list;
	private List<String> options_s;
	private int rating;
	private int count;

	public int getCode() {
		return code;
	}
	public void setCode(int code) {
		this.code = code;
	}
	public String getCategory() {
		return category;
	}
	public void setCategory(String category) {
		this.category = category;
	}
	public String getName() {
		return name;
	}
	public void setName(String name) {
		this.name = name;
	}
	public String getDescr() {
		return descr;
	}
	public void setDescr(String descr) {
		this.descr = descr;
	}
	public List<String> getType() {
		return type;
	}
	public void setType(List<String> type) {
		this.type = type;
	}
	public boolean isSale() {
		return isSale;
	}
	public void setSale(boolean isSale) {
		this.isSale = isSale;
	}
	public String getDetail_desc() {
		return detail_desc;
	}
	public void setDetail_desc(String detail_desc) {
		this.detail_desc = detail_desc;
	}
	public String getMaterial() {
		return material;
	}
	public void setMaterial(String material) {
		this.material = material;
	}
	public String getSize() {
		return size;
	}
	public void setSize(String size) {
		this.size = size;
	}
	public String getManufacturer() {
		return manufacturer;
	}
	public void setManufacturer(String manufacturer) {
		this.manufacturer = manufacturer;
	}
	public String getCaution() {
		return caution;
	}
	public void setCaution(String caution) {
		this.caution = caution;
	}
	public int getPrice() {
		return price;
	}
	public void setPrice(int price) {
		this.price = price;
	}
	public String getPoint() {
		return point;
	}
	public void setPoint(String point) {
		this.point = point;
	}
	public int getStock() {
		return stock;
	}
	public void setStock(int stock) {
		this.stock = stock;
	}
	public String getShipping() {
		return shipping;
	}
	public void setShipping(String shipping) {
		this.shipping = shipping;
	}
	public List<Option> getOptions() {
		return options;
	}
	public void setOptions(List<Option> options) {
		this.options = options;
	}
	public String getType_s() {
		return type_s;
	}
	public void setType_s(String type_s) {
		this.type_s = type_s;
	}
	public String getFilesname() {
		return filesname;
	}
	public void setFilesname(String filesname) {
		this.filesname = filesname;
	}
	public String getMainPhoto() {
		return mainPhoto;
	}
	public void setMainPhoto(String mainPhoto) {
		this.mainPhoto = mainPhoto;
	}
	public String getMainCategory() {
		return mainCategory;
	}
	public void setMainCategory(String mainCategory) {
		this.mainCategory = mainCategory;
	}
	public List<String> getFile_list() {
		return file_list;
	}
	public void setFile_list(List<String> file_list) {
		this.file_list = file_list;
	}
	public List<String> getOptions_s() {
		return options_s;
	}
	public void setOptions_s(List<String> options_s) {
		this.options_s = options_s;
	}
	public int getRating() {
		return rating;
	}
	public void setRating(int rating) {
		this.rating = rating;
	}
	public int getCount() {
		return count;
	}
	public void setCount(int count) {
		this.count = count;
	}
	
	
}
