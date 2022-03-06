package com.gkg.apigateway.model;

import lombok.Data;

@Data
public class TokenResponse {

    private String access_token;
    private Integer expires_in;
    private String refresh_token;
    private Integer refresh_expires_in;
    private String id_token;

}
