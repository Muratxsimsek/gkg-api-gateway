package com.gkg.apigateway.controller;

import com.gkg.apigateway.model.Credential;
import com.gkg.apigateway.model.TokenResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import javax.validation.Valid;

@RestController
@RequestMapping("/auth")
public class TokenController {

    @Value("${gkg.keycloak.url}")
    private String url;

    @Value("${gkg.keycloak.client-id}")
    private String clientId;

    @Value("${gkg.keycloak.client-secret}")
    private String clientSecret;

    @PostMapping("/token")
    public TokenResponse getNewToken(@RequestBody @Valid Credential credential) throws Exception {
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
            map.add("grant_type", "password");
            map.add("client_id", clientId);
            map.add("client_secret", clientSecret);
            map.add("username", credential.getUsername());
            map.add("password", credential.getPassword());
            map.add("scope", "openid");

            HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(map, headers);

            RestTemplate restTemplate = new RestTemplate();

            ResponseEntity<TokenResponse> response = restTemplate
                    .postForEntity(url + "/protocol/openid-connect/token", request, TokenResponse.class);
            TokenResponse TokenResponse = response.getBody();

            return TokenResponse;
        } catch (HttpClientErrorException exception) {
            if (exception.getStatusCode() == HttpStatus.UNAUTHORIZED) {
//                throw new BaseException(BaseErrorCode.AUTHENTICATION_FAILED);
                throw new Exception();
            } else {
//                throw new BaseException(exception);
                exception.printStackTrace();
                throw new Exception();
            }
        }
    }

    @PutMapping("/token")
    public TokenResponse getRefreshToken(@RequestBody @Valid Credential credential) throws Exception {
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
            map.add("grant_type", "refresh_token");
            map.add("client_id", clientId);
            map.add("client_secret", clientSecret);
            map.add("refresh_token", credential.getRefreshToken());

            HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(map, headers);

            RestTemplate restTemplate = new RestTemplate();
            ResponseEntity<TokenResponse> response = restTemplate
                    .postForEntity(url + "/protocol/openid-connect/token", request, TokenResponse.class);
            TokenResponse TokenResponse = response.getBody();

            return TokenResponse;

        } catch (HttpClientErrorException exception) {
            if (exception.getStatusCode() == HttpStatus.BAD_REQUEST) {
//                throw new BaseException(BaseErrorCode.INVALID_REFRESH_TOKEN);
                throw new Exception();
            } else {
//                throw new BaseException(exception);
                throw new Exception();
            }
        }
    }

    @PostMapping("/logout")
    public void logout(@RequestBody @Valid Credential credential) throws Exception {
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
            map.add("client_id", clientId);
            map.add("client_secret", clientSecret);
            map.add("refresh_token", credential.getRefreshToken());

            HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(map, headers);

            RestTemplate restTemplate = new RestTemplate();
            restTemplate.postForEntity(url + "/protocol/openid-connect/logout", request, String.class);
        } catch (HttpClientErrorException exception) {
            if (exception.getStatusCode() == HttpStatus.BAD_REQUEST) {
//                throw new BaseException(BaseErrorCode.INVALID_REFRESH_TOKEN);
                throw new Exception();
            } else {
//                throw new BaseException(exception);
                throw new Exception();
            }
        }
    }
}
