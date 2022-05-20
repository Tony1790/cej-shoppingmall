package com.lcomputerstudy.example.mapper;

import java.util.List;

import org.apache.ibatis.annotations.Mapper;

import com.lcomputerstudy.example.domain.OrderInfo;
import com.lcomputerstudy.example.domain.OrderRequest;
import com.lcomputerstudy.example.domain.ReceiverInfo;
import com.lcomputerstudy.example.domain.UserInfo;

@Mapper
public interface OrderMapper {

	void insertOrderDetails(OrderRequest o);

	void insertOrderInfo(OrderInfo order);

	void insertReceiverInfo(ReceiverInfo receiverInfo);

	int getOrderCode();

	void insertUserInfo_order(UserInfo userInfo);

	List<OrderInfo> getOrderInfo(String id);

	List<OrderRequest> getOrderDetails(int orderCode);

	ReceiverInfo getReceiverInfo(int orderCode);

	UserInfo getUserInfo(int orderCode);

	List<OrderInfo> getOrderInfo_All();

	void deleteFailOrderInfo(String id);

	OrderInfo getOrderinfoById(String id);

	void insertGivePoint(OrderInfo order);

	List<Integer> getTotalSales(String param);

	

	
}
