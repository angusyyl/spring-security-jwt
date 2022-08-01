package com.github.angusyyl;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/***
 * This is a practice on Spring Security with JWT authentication.
 * Reference taken from https://www.javainuse.com/webseries/spring-security-jwt/chap3
 * and https://www.toptal.com/spring/spring-security-tutorial.
 * 
 * @author Angus Yiu
 *
 */
@SpringBootApplication
public class SpringSecurityJwtApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringSecurityJwtApplication.class, args);
	}

}
