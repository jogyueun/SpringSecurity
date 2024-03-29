package org.springsecurity.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springsecurity.Entity.UserEntity;
import org.springsecurity.dto.CustomUserDetails;

import java.io.IOException;

public class JWTFilter extends OncePerRequestFilter {

    private final JWTUtil jwtUtil;

    public JWTFilter(JWTUtil jwtUtil) {

        this.jwtUtil = jwtUtil;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        // request에서 Authorization 헤더를 찾음
        String authorization = request.getHeader("Authorization");

        //Authorization 헤더 검증
        if (authorization == null || !authorization.startsWith("Bearer ")) {

            System.out.println("token null");

            filterChain.doFilter(request, response);
            // 이 필터에서 받은 request, response를 종료하고 다음 필터로 넘겨준다

            //조건이 해당되면 메소드 종료 (필수)
            return;
        }

        System.out.println("authorization now");

        //Bearer 부분 제거 후 순수 토큰만 획득
        String token = authorization.split(" ")[1];

        //토큰 소멸 시간 검증
        if (jwtUtil.isExpired(token)) {

            System.out.println("token expired");

            filterChain.doFilter(request, response);
            // 이 필터에서 받은 request, response를 종료하고 다음 필터로 넘겨준다
            //조건이 해당되면 메소드 종료 (필수)
            return;
        }

        //토큰에서 username과 role 획득
        String username = jwtUtil.getUsername(token);
        String role = jwtUtil.getRole(token);

        //userEntity를 생성하여 값 set
        UserEntity userEntity = new UserEntity();
        userEntity.setUsername(username);
        userEntity.setPassword("temppassword"); // 임시적으로 비밀번호를 넣어준다 // 항상 DB에서 조회해 올 수 없기 때문에
        userEntity.setRole(role);

        // UserDetails에 회원 정보 객체 담기
        // CustomUserDetails 클래스를 사용하여 UserEntity 객체를 활용하여 사용자 세부 정보를 생성합니다.
        CustomUserDetails customUserDetails = new CustomUserDetails(userEntity);

        // 스프링 시큐리티 인증 토큰 생성
        Authentication authToken = new UsernamePasswordAuthenticationToken(customUserDetails, null, customUserDetails.getAuthorities());

        // 세션에 사용자 등록
        // SecurityContextHolder를 사용하여 해당 인증 토큰을 현재의 스레드에 연결된 SecurityContext에 저장합니다.
        // 이렇게 함으로써 Spring Security는 현재 요청의 사용자 정보를 알 수 있게 됩니다.
        SecurityContextHolder.getContext().setAuthentication(authToken);

        // 모든 검증과 인증이 완료되면, 요청은 다음 필터로 전달됩니다.
        // 만약 다음 필터가 없다면, 요청은 애플리케이션의 실제 엔드포인트로 이동하게 됩니다.
        filterChain.doFilter(request, response);
    }
}