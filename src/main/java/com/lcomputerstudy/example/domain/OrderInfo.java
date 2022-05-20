package com.lcomputerstudy.example.domain;

import java.util.List;

public class OrderInfo {

	private int orderCode;	
	private String state;	
	private String payway;	
	private int point;
	private List<OrderRequest> products;
	private ReceiverInfo receiverInfo;
	private int total;
	private UserInfo userInfo;
	private String datetime;
	private int givePoint;
	
	private String user;

	
	public String getUser() {
		return user;
	}
	public void setUser(String user) {
		this.user = user;
	}
	public int getOrderCode() {
		return orderCode;
	}
	public void setOrderCode(int orderCode) {
		this.orderCode = orderCode;
	}
	public String getState() {
		return state;
	}
	public void setState(String state) {
		this.state = state;
	}
	public String getPayway() {
		return payway;
	}
	public void setPayway(String payway) {
		this.payway = payway;
	}
	public int getPoint() {
		return point;
	}
	public void setPoint(int point) {
		this.point = point;
	}
	public List<OrderRequest> getProducts() {
		return products;
	}
	public void setProducts(List<OrderRequest> products) {
		this.products = products;
	}
	public ReceiverInfo getReceiverInfo() {
		return receiverInfo;
	}
	public void setReceiverInfo(ReceiverInfo receiverInfo) {
		this.receiverInfo = receiverInfo;
	}
	public int getTotal() {
		return total;
	}
	public void setTotal(int total) {
		this.total = total;
	}
	public UserInfo getUserInfo() {
		return userInfo;
	}
	public void setUserInfo(UserInfo userInfo) {
		this.userInfo = userInfo;
	}
	public String getDatetime() {
		return datetime;
	}
	public void setDatetime(String datetime) {
		this.datetime = datetime;
	}
	public int getGivePoint() {
		return givePoint;
	}
	public void setGivePoint(int givePoint) {
		this.givePoint = givePoint;
	}	


	
}
