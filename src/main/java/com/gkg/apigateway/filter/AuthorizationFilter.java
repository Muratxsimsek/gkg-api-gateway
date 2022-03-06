package com.gkg.apigateway.filter;

import com.gkg.apigateway.config.SecurityConfig;
import org.keycloak.authorization.client.AuthzClient;
import org.keycloak.representations.idm.authorization.ResourceRepresentation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.*;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Map;

/**
 * Authorizes the request and forwards user context to downstream services in the request header
 */
@ConditionalOnBean(value = SecurityConfig.class)
@Component
public class AuthorizationFilter implements GatewayFilter, Ordered {

    private static final String USER_USERNAME_CLAIM_NAME = "preferred_username";
    private static final String REALM_ACCESS_CLAIM_NAME = "realm_access";
    private static final String USER_ROLES_KEY_NAME = "roles";

    @Value("${gkg.authorization.url}")
    private String authorizationUrl;

    @Autowired
    private AuthzClient authzClient;

    @Autowired
    private RestTemplate restTemplate;

    /**
     * filter with a lower order in the chain will execute its "pre" logic in an
     * earlier stage, but it's "post" implementation will get invoked later
     */
    @Override
    public int getOrder() {
        return Ordered.LOWEST_PRECEDENCE;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        try {
            List<String> authorization = exchange.getRequest().getHeaders().get("Authorization");
            if(authorization != null && authorization.size()>0) {
                List<ResourceRepresentation> byMatchingUri = authzClient.protection().resource()
                        .findByMatchingUri(exchange.getRequest().getMethod() + " " + exchange.getRequest().getPath());
                HttpHeaders hh = new HttpHeaders();
                hh.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
                hh.add("Authorization", exchange.getRequest().getHeaders().get("Authorization").get(0));
                MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
                map.add("grant_type", "urn:ietf:params:oauth:grant-type:uma-ticket");
                map.add("response_mode", "decision");
                map.add("audience", authzClient.getConfiguration().getResource());
                byMatchingUri.stream().forEach(uri -> map.add("permission", uri.getName()));

                HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(map, hh);
                ResponseEntity<String> keyCloakResponse = restTemplate.exchange(authorizationUrl, HttpMethod.POST, entity, String.class);
            }
            return exchange.getPrincipal()
                    .cast(JwtAuthenticationToken.class)
                    .map(JwtAuthenticationToken::getToken)
                    .map(Jwt::getClaims)
                    .map(claims -> setHeaders(exchange, claims))
                    .defaultIfEmpty(exchange)
                    .flatMap(chain::filter);
        }
        catch (HttpClientErrorException exception) {
            if(exception.getStatusCode() == HttpStatus.UNAUTHORIZED) {
//                throw new BaseException(BaseErrorCode.EXPIRED_ACCESS_TOKEN);
                System.out.println("EXPIRED_ACCESS_TOKEN");
            }
            else if(exception.getStatusCode() == HttpStatus.FORBIDDEN) {
//                throw new BaseException(BaseErrorCode.FORBIDDEN);
                System.out.println("FORBIDDEN");
            }
            else if(exception.getStatusCode() == HttpStatus.BAD_REQUEST) {
//                throw new BaseException(BaseErrorCode.BAD_REQUEST);
                System.out.println("BAD_REQUEST");
            }
            else{
                System.out.println("NOTHING");
//                throw new BaseException(exception);
            }
            return null;
        }
    }

    private ServerWebExchange setHeaders(ServerWebExchange exchange, Map<String, Object> claims) {
        //net.minidev.json.JSONObject realmAccess = (net.minidev.json.JSONObject) claims.get(REALM_ACCESS_CLAIM_NAME);
        //net.minidev.json.JSONArray userRolesArray = (net.minidev.json.JSONArray) realmAccess.get(USER_ROLES_KEY_NAME);
        //String userRoles = StringUtils.collectionToCommaDelimitedString(userRolesArray);

        return exchange.mutate()
//                .request(r -> r.header(CommonsConstants.HTTP_HEADER_SUB, (String) claims.get("sub")))
//                .request(r -> r.header(CommonsConstants.HTTP_HEADER_USER_NAME, (String) claims.get(USER_USERNAME_CLAIM_NAME)))
                //.request(r -> r.header(CommonsConstants.HTTP_HEADER_USER_ROLE, userRoles))
                .build();
    }
}

