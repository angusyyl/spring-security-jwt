package com.github.angusyyl;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationListener;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.stereotype.Component;

@Component
public class CustomeSecurityEventListener implements ApplicationListener<AbstractAuthenticationFailureEvent> {
	private static final Logger LOGGER = LoggerFactory.getLogger(CustomeSecurityEventListener.class);

	@Override
	public void onApplicationEvent(AbstractAuthenticationFailureEvent event) {
		LOGGER.info(event.getException().getMessage());
	}

}
