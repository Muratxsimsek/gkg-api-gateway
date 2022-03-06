package com.gkg.apigateway.config;

import org.keycloak.authorization.client.AuthzClient;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

@Configuration
//@ConditionalOnBean(value = SecurityConfig.class)
public class KeycloakConfiguration {

//    @Bean
//    public RestTemplate restTemplate() {
//        RestTemplate restTemplate = new RestTemplate();
//        restTemplate.setRequestFactory(new HttpComponentsClientHttpRequestFactory());
//        return restTemplate;
//    }

    @Bean
    public AuthzClient authzClient() {
        return AuthzClient.create();
    }
}