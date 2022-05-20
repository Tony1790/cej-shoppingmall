package com.lcomputerstudy.example.service;

import java.util.List;

import com.lcomputerstudy.example.domain.QABoard;
import com.lcomputerstudy.example.domain.Review;

public interface BoardService {

	void insertQAPost(QABoard post);

	List<QABoard> getQABoardList();

	QABoard getQAPostDetails(int num);

	void insertAnswerPost(QABoard post);

	void addHit(int num);

	void deletePost(int num);

	void insertReview(Review review);

	List<Review> getReviews(int code);

	void deleteReview(int num);

	List<Review> getReviewList();

	void editReview(Review review);

	int getReviewCount(int i);

	List<Integer> getRatings(int p_code);

	List<Review> getUsersReview(String id);

}
