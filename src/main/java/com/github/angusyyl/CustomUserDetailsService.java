package com.github.angusyyl;

import java.util.NoSuchElementException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.github.angusyyl.dto.AppUser;
import com.github.angusyyl.repository.IUserRepo;

@Service
public class CustomUserDetailsService implements UserDetailsService {

	@Autowired
	private IUserRepo userRepo;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		try {
			AppUser user = userRepo.findByUsername(username);
			return user;
		} catch (NoSuchElementException ex) {
			throw new UsernameNotFoundException(username + " is not found.");
		}
	}

}
