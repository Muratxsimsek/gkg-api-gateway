package com.gkg.apigateway.model;

import lombok.Data;

@Data
public class Credential {

    private String username;
    private String password;
    private String refreshToken;
}
