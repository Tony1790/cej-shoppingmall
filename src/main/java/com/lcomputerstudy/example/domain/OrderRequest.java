package com.lcomputerstudy.example.domain;

public class OrderRequest {

	private int code;
	private int count;
	private String option;
	private Product product;
	private int order_num;
	private String id;
	private int num;
	private int givePoint;
	
	public int getOrder_num() {
		return order_num;
	}
	public void setOrder_num(int order_num) {
		this.order_num = order_num;
	}
	public int getCode() {
		return code;
	}
	public void setCode(int code) {
		this.code = code;
	}
	public int getCount() {
		return count;
	}
	public void setCount(int count) {
		this.count = count;
	}
	public String getOption() {
		return option;
	}
	public void setOption(String option) {
		this.option = option;
	}
	public Product getProduct() {
		return product;
	}
	public void setProduct(Product product) {
		this.product = product;
	}
	public String getId() {
		return id;
	}
	public void setId(String id) {
		this.id = id;
	}
	public int getNum() {
		return num;
	}
	public void setNum(int num) {
		this.num = num;
	}
	public int getGivePoint() {
		return givePoint;
	}
	public void setGivePoint(int givePoint) {
		this.givePoint = givePoint;
	}
	
	
}
