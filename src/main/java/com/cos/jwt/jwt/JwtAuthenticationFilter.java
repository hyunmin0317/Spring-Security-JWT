package com.cos.jwt.jwt;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

// 스프링 시큐리티에서 UsernamePasswordAuthenticationFilter 가 있음
// login 요청으로 username, password 전송 (POST) -> UsernamePasswordAuthenticationFilter 동작 함
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    // login 요청을 하면 로그인 시도를 위해서 실행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("JwtAuthenticationFilter::로그인 시도중");

        // 1. username, password 받아서

        // 2. 정상 인지 로그인 시도
        // authenticationManager 로 로그인 시도 -> PrincipalDetailService 가 호출 loadUserByUsername() 함수 실행

        // 3. PrincipalDetails 를 세션에 담음 (권한 관리)

        // 4. JWT 토큰을 만들어 응답

        return super.attemptAuthentication(request, response);
    }
}
