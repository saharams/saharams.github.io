---
layout: post
title: Security filter Chain
date: 2024-02-16 17:14:00 +0900
description: You’ll find this post in your `_posts` directory. Go ahead and edit it and re-build the site to see your changes. # Add post description (optional)
img: security.jpg # Add image post (optional)
tags: [Productivity, Software] # add tag
---

# Security filter Chain

보안 필터 체인은 웹 애플리케이션의 요청과 응답 처리에 사용되는 보안 필터들의 모음이다. 이 체인은 순차적으로 보안 관련 작업을 수행하며, 이에는 인증, 권한 부여, 로깅 등이 포함된다. 각 필터는 특정 작업을 수행한 후에 요청과 응답을 체인의 다음 필터로 전달한다.

![Untitled](/assets/img/Untitled.png)



기본적인 Servlet Filter는 Spring Application과는 별도이기 때문에, Bean 객체를 찾지 못한다.

- 그래서 Spring에서는 DelegatingFilterProxy를 활용해 Bean 객체를 찾을 수 있는
Filter를 만들게 해준다



Spring Security는 이 DelegatingFilterProxy를 활용해, FilterChainProxy를 등록한다.

- FilterChainProxy에는 다시 우리가 구성한 SecurityFilterChain이 등록된다.
- 그리고 이 SecurityFilterChain에 우리가 만든 Filter를 등록하고, 인증을 진행할 수
있다.

![Untitled](/assets/img/Untitled 2.png)

### 구현 예시

```java
import com.example.auth.entity.CustomUserDetails;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.ArrayList;

// 모든 요청이 인증된 요청으로 취급하는 필터
@Slf4j
public class AllAuthenticatedFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {
        log.info("try all auth filter");
        // 헤더에 `x-likelion-all-auth: true`가 포함된 요청은 로그인 한 요청이다.
        String header = request.getHeader("x-likelion-all-auth");
        if (header != null) {
            // 사용자의 인증정보를 담고있는 객체
            SecurityContext context = SecurityContextHolder.createEmptyContext();
            AbstractAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(
                            CustomUserDetails.builder()
                                    .username(header)
                                    .password("아무거나")
                                    .email("edujeeho@gmail.com")
                                    .phone("010-12345678")
                                    .build(),
                            "아무거나", new ArrayList<>()
                    );
            // SecurityContext에 사용자 정보를 등록해준다.
            context.setAuthentication(authentication);
            SecurityContextHolder.setContext(context);
            log.info("set security context with header");
        } else {
            log.info("all auth required header is absent");
        }
        // 필터를 실행을 해주어야 한다. 실패하든 말든.
        filterChain.doFilter(request, response);
    }
}
```

 OncePerRequestFilter 를 상속받아 http request의 한 번의 요청에 대해 한번만 실행하는  

AllAuthenticatedFilter 라는 필터를 만들었다. 이는 다시 @Configuration과 @Bean을 통해 Bean에 등록된 WebSecurityConfig클래스 의   .addFilterBefore(
                        new AllAuthenticatedFilter(),
                        AuthorizationFilter.class 을 통해 추가되어서 실행된다.

```java
import com.example.auth.filters.AllAuthenticatedFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.web.bind.annotation.RequestMethod;

// @Bean을 비롯해서 여러 설정을 하기 위한 Bean 객체
@Configuration
public class WebSecurityConfig {

    // 메서드의 결과를 Bean 객체로 관리해주는 어노테이션
    @Bean
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http
    ) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(
                        // /no-auth로 오는 요청은 모두 허가
                        auth -> auth
                                // 어떤 경로에 대한 설정인지
                                .requestMatchers(
                                        "/no-auth",
                                        "/users/home",
                                        "/tests"
                                )
                                // 이 경로에 도달할 수 있는 사람에 대한 설정(모두)
                                .permitAll()
                                .requestMatchers("/users/my-profile")
                                .authenticated()
                                .requestMatchers(
                                        "/users/login",
                                        "/users/register"
                                )
                                .anonymous()
                                .anyRequest()
                                .authenticated()
                        // .anyRequest().permitAll()
                )
                // html form 요소를 이용해 로그인을 시키는 설정
                .formLogin(
                        formLogin -> formLogin
                                // 어떤 경로(URL)로 요청을 보내면
                                // 로그인 페이지가 나오는지
                                .loginPage("/users/login")
                                // 아무 설정 없이 로그인에 성공한 뒤
                                // 이동할 URL
                                .defaultSuccessUrl("/users/my-profile")
                                // 실패시 이동할 URL
                                .failureUrl("/users/login?fail")
                )
                // 로그아웃 설정
                .logout(
                        logout -> logout
                                // 어떤 경로(URL)로 요청을 보내면 로그아웃이 되는지
                                // (사용자의 세션을 삭제할지)
                                .logoutUrl("/users/logout")
                                // 로그아웃 성공시 이동할 페이지
                                .logoutSuccessUrl("/users/home")
                )
                // 특정 필터 앞에 나만의 필터를 넣는다.
                .addFilterBefore(
                        new AllAuthenticatedFilter(),
                        AuthorizationFilter.class
                )
        ;

        return http.build();
    }

    @Bean
    // 비밀번호 암호화 클래스
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    //    @Bean
    // 사용자 정보 관리 클래스
    public UserDetailsManager userDetailsManager(
            PasswordEncoder passwordEncoder
    ) {
        // 사용자 1
        UserDetails user1 = User.withUsername("user1")
                .password(passwordEncoder.encode("password1"))
                .build();
        // Spring Security에서 기본으로 제공하는,
        // 메모리 기반 사용자 관리 클래스 + 사용자 1
        return new InMemoryUserDetailsManager(user1);
    }
}
```

Postman을 이용한 테스트 결과

![Untitled](/assets/img/Untitled 3.png)

인텔리제이에서 생성된 유저의 정보

![Untitled](/assets/img/Untitled 4.png)