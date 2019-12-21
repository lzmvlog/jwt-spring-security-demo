package org.zerhusen.security.jwt;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

/**
 * Filters incoming requests and installs a Spring Security principal if a header corresponding to a valid user is
 * found.
 */
public class JWTFilter extends GenericFilterBean {

   private static final Logger LOG = LoggerFactory.getLogger(JWTFilter.class);

   public static final String AUTHORIZATION_HEADER = "Authorization";

   private TokenProvider tokenProvider;

   public JWTFilter(TokenProvider tokenProvider) {
      this.tokenProvider = tokenProvider;
   }

   /**
    * 这里就是 如果你有JWT 那我让你解析 jwt 然后认证,
    * 如果没有 jwt 你还是像普通请求一样,只是未登录
    * @param servletRequest
    * @param servletResponse
    * @param filterChain
    * @throws IOException
    * @throws ServletException
    */
   @Override
   public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain)
      throws IOException, ServletException {
      // 拿到 request
      HttpServletRequest httpServletRequest = (HttpServletRequest) servletRequest;
      // 这里就是获取到token
      String jwt = resolveToken(httpServletRequest);
      // 获取到URI 请求路由地址 记录LOG
      String uri = httpServletRequest.getRequestURI();
      // 如果 jwt不为空 然后调用了 jwtUtil 效验了 token 是否有效
      if (StringUtils.hasText(jwt) && tokenProvider.validateToken(jwt)) {
         // 获取 Authentication
         Authentication authentication = tokenProvider.getAuthentication(jwt);
         // 将 认证信息重新set 到 security context 中
         SecurityContextHolder.getContext().setAuthentication(authentication);
         LOG.debug("set Authentication to security context for '{}', uri: {}", authentication.getName(), uri);
      } else {
         LOG.debug("no valid JWT token found, uri: {}", uri);
      }
      // 拦截器继续执行,
      filterChain.doFilter(servletRequest, servletResponse);
   }

   private String resolveToken(HttpServletRequest request) {
      // 从头部信息拿到 Authorization 的内容
      String bearerToken = request.getHeader(AUTHORIZATION_HEADER);
      // 如果 不为空, 且 Bearer 开头, 注意有个空格,
      if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
         // 这里的 7长度就是 "Bearer " 的长度
         return bearerToken.substring(7);
      }
      return null;
   }
}
