package com.github.angusyyl.repository;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;

import com.github.angusyyl.dto.AppUser;

/***
 * This is just a practice. So real DB connection is skipped.
 * @author Angus Yiu
 *
 */
@Service
public class UserRepoImpl implements IUserRepo {
	private static final Logger LOGGER = LoggerFactory.getLogger(UserRepoImpl.class);

	private List<AppUser> users = new ArrayList<AppUser>();

	public UserRepoImpl() {
		Collection<? extends GrantedAuthority> andyAuthorities = Arrays
				.asList(new SimpleGrantedAuthority("ROLE_ADMIN"));
		Collection<? extends GrantedAuthority> lucyAuthorities = Arrays.asList(new SimpleGrantedAuthority("ROLE_USER"));
		this.users.add(new AppUser("andy", "1234", 20, andyAuthorities));
		this.users.add(new AppUser("lucy", "1234", 18, lucyAuthorities));
	}

	public AppUser findByUsername(String username) {
		AppUser user = this.users.stream().filter(u -> username.equals(u.getUsername())).findFirst().orElseThrow();
		return user;
	}

	public List<AppUser> findAll() {
		return this.users;
	}

	public String add(AppUser user) {
		this.users.add(user);
		LOGGER.info("Added new user {}.", user.getUsername());
		return user.getUsername();
	}

}
