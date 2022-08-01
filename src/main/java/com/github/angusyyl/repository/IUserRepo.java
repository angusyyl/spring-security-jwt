package com.github.angusyyl.repository;

import java.util.List;

import org.springframework.stereotype.Repository;

import com.github.angusyyl.dto.AppUser;

@Repository
public interface IUserRepo {
	public AppUser findByUsername(String username);
	public List<AppUser> findAll();
	public String add(AppUser user);
}
