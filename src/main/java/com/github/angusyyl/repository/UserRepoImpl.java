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
 * 
 * @author Angus Yiu
 *
 */
@Service
public class UserRepoImpl implements IUserRepo {
	private static final Logger LOGGER = LoggerFactory.getLogger(UserRepoImpl.class);

	private List<AppUser> users = new ArrayList<AppUser>();

	public UserRepoImpl() {
		Collection<? extends GrantedAuthority> andyAuthorities = Arrays.asList(new SimpleGrantedAuthority("ROLE_ADMIN"),
				new SimpleGrantedAuthority("ROLE_IT_ADMIN"));
		Collection<? extends GrantedAuthority> katieAuthorities = Arrays
				.asList(new SimpleGrantedAuthority("ROLE_ADMIN"), new SimpleGrantedAuthority("ROLE_HR_ADMIN"));
		Collection<? extends GrantedAuthority> lucyAuthorities = Arrays.asList(new SimpleGrantedAuthority("ROLE_USER"));
		Collection<? extends GrantedAuthority> samAuthorities = Arrays.asList(new SimpleGrantedAuthority("ROLE_USER"),
				new SimpleGrantedAuthority("ROLE_CANDIDATE"));

		this.users.add(new AppUser("andy", "1234", 50, "IT Manager", andyAuthorities));
		this.users.add(new AppUser("katie", "1234", 28, "HR Manager", katieAuthorities));
		this.users.add(new AppUser("lucy", "1234", 18, "HR Officer", lucyAuthorities));
		this.users.add(new AppUser("sam", "1234", 18, "Software Engineer", samAuthorities));
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
