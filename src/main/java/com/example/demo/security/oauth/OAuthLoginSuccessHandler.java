package com.example.demo.security.oauth;

import com.example.demo.repository.UserRepository;
import com.example.demo.security.jwt.JWTUtil;
import com.example.demo.service.general.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;

@Slf4j
@Component
@RequiredArgsConstructor
public class OAuthLoginSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final UserService userService;
    private final JWTUtil jwtUtil;
    private final UserRepository userRepository;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        // 1. 인가 코드 추출
        // 2. 카카오에 토큰 요청
        // 3. 카카오에서 토큰 받아오기
        // 4. 카카오에 사용자 정보 요청

        // 5. 사용자 정보 받아오기
        Object principal = authentication.getPrincipal();

        if (!(principal instanceof OidcUser oidcUser)) {
            log.error("OidcUser가 아님. id_token을 추출할 수 없습니다.");
            response.sendRedirect("https://www.jangmadang.site/error");
            return;
        }
        // id_token 추출
        String idToken = oidcUser.getIdToken().getTokenValue();
        log.info("카카오 id_token 추출 완료: {}", idToken);


        // 6. 사용자 정보 확인
        Map<String, Object> kakaoAccount = (Map<String, Object>) oidcUser.getAttributes().get("kakao_account");
        String email = kakaoAccount.get("email").toString();
        log.info("로그인 이메일: {}", email);

        // 신규 회원
        if (!userService.isExistUserByEmail(email)) {
            HttpSession session = request.getSession();
            log.info("세션아이디 {}", session);
            session.setAttribute("oauthEmail", email);
            log.info("세션값 {}", session.getAttribute("oauthEmail"));
            response.sendRedirect("https://www.jangmadang.site/kakao");
            return;
        }


        // 엑세스 토큰 생성
        Long userId = userService.findIdByEmail(email);
        String accessToken = jwtUtil.createAccessToken("access", userId, email);
        String refreshToken = jwtUtil.createRefreshToken("refresh", userId, email);

        userService.addRefreshToken(userId, refreshToken); // 리프레시 토큰 저장

        response.addCookie(jwtUtil.createCookie("access", accessToken, 24 * 60 * 60));
        response.addCookie(jwtUtil.createCookie("refresh", refreshToken, 7 * 24 * 60 * 60));
        response.addCookie(jwtUtil.createCookie("id_token", idToken, 300));
        log.info("쿠키 전달 완료");

        response.sendRedirect("https://www.jangmadang.site");

    }
}
