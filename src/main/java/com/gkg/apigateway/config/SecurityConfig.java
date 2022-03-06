package com.gkg.apigateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@EnableWebFluxSecurity
//@ConditionalOnProperty(prefix = "tams.security", name = "enabled", havingValue = "true")
public class SecurityConfig {
    
    public final String ignoredPaths[] = {"/swagger-ui/**", "/actuator/**", "/auth/**","/gkg-rm-core/consumer/message/**",
            "/tams-task-manager/gantt-websocket/**", "/tams-daily-flight-manager/web-socket/**",
            "/tams-rule-manager/gantt-websocket/**","/tams-daily-flight-manager/v1/trcp/**"};

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        return http.httpBasic().disable()
            .csrf().disable()
            .cors()
            .and()
                .authorizeExchange()
                .pathMatchers(this.ignoredPaths).permitAll()
                .anyExchange().authenticated()
            .and()
                .oauth2Client().and().oauth2ResourceServer().jwt()
            .and()
//                .authenticationEntryPoint((exchange, exception) -> Mono.error(new BaseException(BaseErrorCode.INVALID_ACCESS_TOKEN)))
//                .accessDeniedHandler(((exchange, exception) -> Mono.error(new BaseException(BaseErrorCode.FORBIDDEN))))
            .and()
                .build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList("*"));
        configuration.setAllowedMethods(Arrays.asList("*"));
        configuration.setAllowedHeaders(Arrays.asList("*"));
        configuration.setMaxAge(31536000L); // 1 year
        configuration.setAllowCredentials(true);

        List<String> exposedHeaders = new ArrayList<>();
        exposedHeaders.add("TAMS-UTC-TIME");
        exposedHeaders.add("Content-Disposition");
        configuration.setExposedHeaders(exposedHeaders);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

}
