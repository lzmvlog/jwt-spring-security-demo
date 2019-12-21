package org.zerhusen.security.jwt;

import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

public class JWTConfigurer extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {

    private TokenProvider tokenProvider;

    public JWTConfigurer(TokenProvider tokenProvider) {
        this.tokenProvider = tokenProvider;
    }

   @Override
   public void configure(HttpSecurity http) {
      // 实例化 JwtFilter 拦截器, 将Token util bean 传递过来
      JWTFilter customFilter = new JWTFilter(tokenProvider);
      // 将这个 jwt filter 配置在 UsernamePasswordAuthenticationFilter.class 之前
      http.addFilterBefore(customFilter, UsernamePasswordAuthenticationFilter.class);
   }
}
