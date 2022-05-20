package com.lcomputerstudy.example.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.lcomputerstudy.example.domain.Point;
import com.lcomputerstudy.example.mapper.PointMapper;

@Service
public class PointServiceImpl implements PointService {

	@Autowired
	PointMapper pointMapper;

	@Override
	public void insertPoint(Point point_) {
		pointMapper.insertPoint(point_);
	}

	@Override
	public List<Point> getPointList() {
		// TODO Auto-generated method stub
		return pointMapper.getPointList();
	}
}
