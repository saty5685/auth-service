package com.deezyWallet.auth_service.entities;

public enum Role {
	USER(1);

	public int id;
    private Role(int id){
		this.id=id;
	}

	public int getId() {
		return id;
	}

	public static Role getEnumById(int id){
		switch (id){
			case 1 -> {return Role.USER;}
			default ->{ return null;}
		}
	}

}
