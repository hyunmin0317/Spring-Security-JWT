package com.cos.jwt.config;

import com.cos.jwt.jwt.JwtAuthenticationFilter;
import com.cos.jwt.jwt.JwtAuthorizationFilter;
import com.cos.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.filter.CorsFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final CorsFilter corsFilter;
    private final AuthenticationConfiguration configuration;
    private final UserRepository userRepository;

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
                .requestMatchers("/api/v1/manager/**").hasAnyRole("ADMIN", "MANAGER")
                .requestMatchers("/api/v1/admin/**").hasRole("ADMIN")
                .anyRequest().permitAll()
        );

        // filter 등록 예시
//        http.addFilterBefore(new MyFilter3(), SecurityContextHolderFilter.class);
//        http.addFilterAfter(new MyFilter4(), BasicAuthenticationFilter.class);
//        http.addFilterBefore(new JwtFilter(), SecurityContextHolderFilter.class);

        // Jwt Filter (with login)
        AuthenticationManager authenticationManager = configuration.getAuthenticationManager();
        http.addFilter(new JwtAuthenticationFilter(authenticationManager));
        http.addFilter(new JwtAuthorizationFilter(authenticationManager, userRepository));

        return http.build();
    }
}
