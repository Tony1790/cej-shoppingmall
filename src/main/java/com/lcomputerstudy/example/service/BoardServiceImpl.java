package com.lcomputerstudy.example.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.lcomputerstudy.example.domain.QABoard;
import com.lcomputerstudy.example.domain.Review;
import com.lcomputerstudy.example.mapper.BoardMapper;

@Service
public class BoardServiceImpl implements BoardService{

	@Autowired
	BoardMapper boardmapper;
	
	@Override
	public void insertQAPost(QABoard post) {
		boardmapper.insertQAPost1(post);
		boardmapper.insertQAPost2(post);
		
	}

	@Override
	public List<QABoard> getQABoardList() {
		// TODO Auto-generated method stub
		return boardmapper.getQABoardList();
	}

	@Override
	public QABoard getQAPostDetails(int num) {
		// TODO Auto-generated method stub
		return boardmapper.getQAPostDetails(num);
	}

	@Override
	public void insertAnswerPost(QABoard post) {
		boardmapper.insertAnswerPost1(post);
		boardmapper.insertAnswerPost2(post);
		
	}

	@Override
	public void addHit(int num) {
		boardmapper.addHit(num);
		
	}

	@Override
	public void deletePost(int num) {
		boardmapper.deletePost(num);
		
	}

	@Override
	public void insertReview(Review review) {
		boardmapper.insertReview(review);
		
	}

	@Override
	public List<Review> getReviews(int code) {
		// TODO Auto-generated method stub
		return boardmapper.getReviews(code);
	}

	@Override
	public void deleteReview(int num) {
		boardmapper.deleteReview(num);
		
	}

	@Override
	public List<Review> getReviewList() {
		// TODO Auto-generated method stub
		return boardmapper.getReviewList();
	}

	@Override
	public void editReview(Review review) {
		boardmapper.editReview(review);
		
	}

	@Override
	public int getReviewCount(int p_code) {
		// TODO Auto-generated method stub
		return boardmapper.getReviewCount(p_code);
	}

	@Override
	public List<Integer> getRatings(int p_code) {
		// TODO Auto-generated method stub
		return boardmapper.getRatings(p_code);
	}

	@Override
	public List<Review> getUsersReview(String id) {
		// TODO Auto-generated method stub
		return boardmapper.getUsersReview(id);
	}

}
