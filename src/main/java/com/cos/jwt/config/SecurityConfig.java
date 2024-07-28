package com.cos.jwt.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        // csrf disable
        http.csrf(AbstractHttpConfigurer::disable);

        // form 로그인 방식 disable
        http.formLogin(AbstractHttpConfigurer::disable);

        // http basic 인증 방식 disable
        http.httpBasic(AbstractHttpConfigurer::disable);

        // 세션 사용 안함
        http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        // 경로별 인가 작업
        http.authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/api/v1/user/**").authenticated()
                .requestMatchers("/api/v1//manager/**").hasAnyRole("ADMIN", "MANAGER")
                .requestMatchers("/api/v1//admin/**").hasRole("ADMIN")
                .anyRequest().permitAll()
        );

        return http.build();
    }
}
