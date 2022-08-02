package com.github.angusyyl;

public class RefreshTokenReq {
	private String refreshToken;

	public RefreshTokenReq() {
	}
	
	public RefreshTokenReq(String refreshToken) {
		this.refreshToken = refreshToken;
	}

	public String getRefreshToken() {
		return refreshToken;
	}

	public void setRefreshToken(String refreshToken) {
		this.refreshToken = refreshToken;
	}

}
