package com.lcomputerstudy.example.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.lcomputerstudy.example.domain.OrderInfo;
import com.lcomputerstudy.example.domain.OrderRequest;
import com.lcomputerstudy.example.domain.ReceiverInfo;
import com.lcomputerstudy.example.domain.UserInfo;
import com.lcomputerstudy.example.mapper.OrderMapper;

@Service
public class OrderServiceImpl implements OrderService {

	@Autowired
	OrderMapper orderMapper;
	
	@Override
	public void insertOrderDetails(OrderRequest o) {
		orderMapper.insertOrderDetails(o);
		
	}

	@Override
	public void insertOrderInfo(OrderInfo order) {
		orderMapper.insertOrderInfo(order);
		
	}

	@Override
	public void insertReceiverInfo(ReceiverInfo receiverInfo) {
		orderMapper.insertReceiverInfo(receiverInfo);
		
	}

	@Override
	public int getOrderCode() {
		// TODO Auto-generated method stub
		return orderMapper.getOrderCode();
	}


	@Override
	public void insertUserInfo_order(UserInfo userInfo) {
		orderMapper.insertUserInfo_order(userInfo);
		
	}

	@Override
	public List<OrderInfo> getOrderInfo(String id) {
		// TODO Auto-generated method stub
		return orderMapper.getOrderInfo(id);
	}

	@Override
	public List<OrderRequest> getOrderDetails(int orderCode) {
		// TODO Auto-generated method stub
		return orderMapper.getOrderDetails(orderCode);
	}

	@Override
	public ReceiverInfo getReceiverInfo(int orderCode) {
		// TODO Auto-generated method stub
		return orderMapper.getReceiverInfo(orderCode);
	}

	@Override
	public UserInfo getUserInfo(int orderCode) {
		// TODO Auto-generated method stub
		return orderMapper.getUserInfo(orderCode);
	}

	@Override
	public List<OrderInfo> getOrderInfo_All() {
		// TODO Auto-generated method stub
		return orderMapper.getOrderInfo_All();
	}

	@Override
	public void deleteFailOrderInfo(String id) {
		orderMapper.deleteFailOrderInfo(id);
		
	}

	@Override
	public OrderInfo getOrderinfoById(String id) {
		// TODO Auto-generated method stub
		return 	orderMapper.getOrderinfoById(id);
	}

	@Override
	public void insertGivePoint(OrderInfo order) {
		orderMapper.insertGivePoint(order);
		
	}

	@Override
	public List<Integer> getTotalSales(String param) {
		// TODO Auto-generated method stub
		return orderMapper.getTotalSales(param);
	}



}
