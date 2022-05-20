package com.lcomputerstudy.example.service;

import java.util.List;

import com.lcomputerstudy.example.domain.Point;

public interface PointService {

	void insertPoint(Point point_);

	List<Point> getPointList();

}
