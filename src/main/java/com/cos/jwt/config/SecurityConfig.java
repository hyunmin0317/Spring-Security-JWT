package com.cos.jwt.config;

import com.cos.jwt.filter.JwtFilter;
import com.cos.jwt.filter.MyFilter3;
import com.cos.jwt.filter.MyFilter4;
import com.cos.jwt.jwt.JwtAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.web.filter.CorsFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final CorsFilter corsFilter;
    private final AuthenticationConfiguration configuration;

    @Bean
    public BCryptPasswordEncoder encoder() {
        return new BCryptPasswordEncoder();
    }

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

        // cors 필터 추가
        // 안증 O -> 시큐리티 필터에 등록, 인증 X -> @CrossOrigin
        http.addFilter(corsFilter);

        // 경로별 인가 작업
        http.authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/api/v1/user/**").authenticated()
                .requestMatchers("/api/v1//manager/**").hasAnyRole("ADMIN", "MANAGER")
                .requestMatchers("/api/v1//admin/**").hasRole("ADMIN")
                .anyRequest().permitAll()
        );

        // filter 등록 예시
        http.addFilterBefore(new MyFilter3(), SecurityContextHolderFilter.class);
        http.addFilterAfter(new MyFilter4(), BasicAuthenticationFilter.class);

        // AuthenticationManager
        http.addFilterAt(new JwtAuthenticationFilter(configuration.getAuthenticationManager()), UsernamePasswordAuthenticationFilter.class);

        // Jwt Filter (with login)
        http.addFilterBefore(new JwtFilter(), SecurityContextHolderFilter.class);

        return http.build();
    }
}
