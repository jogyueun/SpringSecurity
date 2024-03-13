package org.springsecurity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springsecurity.jwt.JWTUtil;
import org.springsecurity.jwt.LoginFilter;

@Configuration  // configuration Bean 등록
@EnableWebSecurity // Security 를 위한 어노테이션
public class SecurityConfig {

    //AuthenticationManager가 인자로 받을 AuthenticationConfiguraion 객체 생성자 주입
    private final AuthenticationConfiguration authenticationConfiguration;

    private final JWTUtil jwtUtil;

    public SecurityConfig(AuthenticationConfiguration authenticationConfiguration, JWTUtil jwtUtil) {

        this.authenticationConfiguration = authenticationConfiguration;
        this.jwtUtil = jwtUtil;
    }

    //AuthenticationManager Bean 등록
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {

        return configuration.getAuthenticationManager();
    }


    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {

        return new BCryptPasswordEncoder();
    }
    // security 를 통해서 회원정보 로그인, 검증, 접속 할때는 비밀번호를 항상 캐시로 암호화하고 검증해서 진행한다.

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {



        //csrf disable
        http
                .csrf((auth) -> auth.disable());

        // 세션 방식에서는 세션이 항상 고정되어 있기 때문에 csrf 공격을 필수적으로 방어를 해줘야 한다.
        // jwt 방식에서는 세션이 STATELESS 상태 이기 때문에 csrf를 안 건드려두 된다.

        //Form 로그인 방식 disable
        http
                .formLogin((auth) -> auth.disable());

        //http basic 인증 방식 disable
        http
                .httpBasic((auth) -> auth.disable());
        // jwt 방식으로 로그인 할거기 때문에 Form, Basic 로그인 방식을 비활성화 한다.

        //경로별 인가 작업 (특정한 경로에 대하여 권한이 있는 사용자만 접근 가능하게 설정한다.)
        http
                .authorizeHttpRequests((auth) -> auth
                        .requestMatchers("/login", "/", "/join").permitAll()
                        .requestMatchers("/admin").hasRole("ADMIN")
                        .requestMatchers("/user").hasRole("USER")
                        .anyRequest().authenticated()); // 위의 세 개의 경로를 제외한 다른 경로는 로그인한 사용자만 접근 가능!

        //필터 추가 LoginFilter()는 인자를 받음 (AuthenticationManager() 메소드에 authenticationConfiguration 객체를 넣어야 함) 따라서 등록 필요
        http
                .addFilterAt(new LoginFilter(authenticationManager(authenticationConfiguration), jwtUtil), UsernamePasswordAuthenticationFilter.class);

        //세션 설정
        http
                .sessionManagement((session) -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        // jwt 방식에서는 세션을 항삭 STATELESS 상태로 관리 해야 한다. 제일 중요!!!

        return http.build();
    }
}