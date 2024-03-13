package org.springsecurity.jwt;

import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Date;

// 0.12.3 버전

@Component
public class JWTUtil {

    private SecretKey secretKey;

    // 이 생성자는 Spring의 @Value 어노테이션을 사용하여 application.yml 파일에서 JWT 시크릿 키를 가져옵니다.
    public JWTUtil(@Value("${spring.jwt.secret}")String secret) {


        secretKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), Jwts.SIG.HS256.key().build().getAlgorithm());
    }

    // 주어진 JWT 토큰에서 사용자 이름을 추출하여 반환합니다.
    // JWT 토큰은 Base64로 인코딩된 헤더, 페이로드 및 서명 부분으로 구성되며, 이 메서드는 페이로드에서 사용자 이름을 추출합니다.
    public String getUsername(String token) {

        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("username", String.class);
    }

    // 주어진 JWT 토큰에서 사용자 역할을 추출하여 반환합니다.
    // 이 메서드도 마찬가지로 페이로드에서 역할을 추출합니다.
    public String getRole(String token) {

        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("role", String.class);
    }

    // 주어진 JWT 토큰이 만료되었는지를 확인합니다.
    // 토큰의 만료 시간이 현재 시간보다 이전인 경우 토큰은 만료되었습니다.
    public Boolean isExpired(String token) {

        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().getExpiration().before(new Date());
    }

    // 주어진 사용자 이름, 역할 및 만료 시간을 사용하여 JWT를 생성합니다.
    // JWT를 생성할 때는 페이로드에 사용자 이름과 역할을 추가하고, 토큰의 발급 시간 및 만료 시간을 설정합니다.
    // 그런 다음 생성된 JWT에 서명하여 반환합니다.
    public String createJwt(String username, String role, Long expiredMs) {

        return Jwts.builder()
                .claim("username", username)
                .claim("role", role)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + expiredMs))
                .signWith(secretKey)
                .compact();
    }
}


// 0.11.5 버전!!

//@Component
//public class JWTUtil {
//
//    private Key key;
//
//    public JWTUtil(@Value("${spring.jwt.secret}")String secret) {
//
//
//        byte[] byteSecretKey = Decoders.BASE64.decode(secret);
//        key = Keys.hmacShaKeyFor(byteSecretKey);
//    }
//
//    public String getUsername(String token) {
//
//        return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody().get("username", String.class);
//    }
//
//    public String getRole(String token) {
//
//        return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody().get("role", String.class);
//    }
//
//    public Boolean isExpired(String token) {
//
//        return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody().getExpiration().before(new Date());
//    }
//
//    public String createJwt(String username, String role, Long expiredMs) {
//
//        Claims claims = Jwts.claims();
//        claims.put("username", username);
//        claims.put("role", role);
//
//        return Jwts.builder()
//                .setClaims(claims)
//                .setIssuedAt(new Date(System.currentTimeMillis()))
//                .setExpiration(new Date(System.currentTimeMillis() + expiredMs))
//                .signWith(key, SignatureAlgorithm.HS256)
//                .compact();
//    }
//}