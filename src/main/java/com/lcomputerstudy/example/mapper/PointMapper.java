package com.lcomputerstudy.example.mapper;

import java.util.List;

import org.apache.ibatis.annotations.Mapper;

import com.lcomputerstudy.example.domain.Point;

@Mapper
public interface PointMapper {

	void insertPoint(Point point);

	List<Point> getPointList();

}
