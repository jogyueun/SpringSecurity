package org.springsecurity.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class CorsMvcConfig implements WebMvcConfigurer {

    @Override
    public void addCorsMappings(CorsRegistry corsRegistry) {

        corsRegistry.addMapping("/**")
                .allowedOrigins("http://localhost:3000");
        // 우리의 모든 경로에 대해서 로컬호스트 3000번에서 오는 요청을 허용한다.
    }
}

// 위의 코드는 Spring MVC 애플리케이션에서 CORS(Cross-Origin Resource Sharing)를 구성하는 방법을 보여줍니다.
// CORS는 웹 애플리케이션의 보안 정책 중 하나로, 다른 도메인의 리소스 요청을 허용하거나 거부하는 것을 관리합니다.
// 이 코드는 모든 경로(/**)에 대해 특정 origin(여기서는 http://localhost:3000)에서 오는 요청을 허용하는 CORS 구성을 추가합니다.