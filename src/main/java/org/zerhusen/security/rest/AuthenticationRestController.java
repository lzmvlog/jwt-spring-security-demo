package org.zerhusen.security.rest;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.zerhusen.security.rest.dto.LoginDto;
import org.zerhusen.security.jwt.JWTFilter;
import org.zerhusen.security.jwt.TokenProvider;

import javax.validation.Valid;

/**
 * Controller to authenticate users.
 */
@RestController
@RequestMapping("/api")
public class AuthenticationRestController {

   private final TokenProvider tokenProvider;

   private final AuthenticationManagerBuilder authenticationManagerBuilder;

   public AuthenticationRestController(TokenProvider tokenProvider, AuthenticationManagerBuilder authenticationManagerBuilder) {
      this.tokenProvider = tokenProvider;
      this.authenticationManagerBuilder = authenticationManagerBuilder;
   }

   /**
    * 这里是之前忽略的认证请求URL
    * @param loginDto
    * @return
    */
   @PostMapping("/authenticate")
   public ResponseEntity<JWTToken> authorize(@Valid @RequestBody LoginDto loginDto) {

      // 封装一个 UsernamePasswordAuthenticationToken 是不是很像拦截器那里做了一次的事情, 区别在于传递了密码
      UsernamePasswordAuthenticationToken authenticationToken =
         new UsernamePasswordAuthenticationToken(loginDto.getUsername(), loginDto.getPassword());

      // 这里是自己认证了 这个 authenticationToken 最后会传递到 org.zerhusen.security.UserModelDetailsService 拦截器去验证登录
      Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);
      // 设置 认证完成后的用户信息
      SecurityContextHolder.getContext().setAuthentication(authentication);
      // 看看是否勾选了 记住我
      boolean rememberMe = (loginDto.isRememberMe() == null) ? false : loginDto.isRememberMe();
      // 如果勾选了 记住我, 让token 的生效期会长一些, 这里是 token 构建时候的配置 , 可以进去看 jwt util 的内容
      String jwt = tokenProvider.createToken(authentication, rememberMe);
      // 这一步没啥必要 最后body 中也返回了
      HttpHeaders httpHeaders = new HttpHeaders();
      httpHeaders.add(JWTFilter.AUTHORIZATION_HEADER, "Bearer " + jwt);

      return new ResponseEntity<>(new JWTToken(jwt), httpHeaders, HttpStatus.OK);
   }

   /**
    * Object to return as body in JWT Authentication.
    */
   static class JWTToken {

      private String idToken;

      JWTToken(String idToken) {
         this.idToken = idToken;
      }

      @JsonProperty("id_token")
      String getIdToken() {
         return idToken;
      }

      void setIdToken(String idToken) {
         this.idToken = idToken;
      }
   }
}
