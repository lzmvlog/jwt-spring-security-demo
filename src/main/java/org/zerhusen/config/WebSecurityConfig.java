package org.zerhusen.config;

import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.filter.CorsFilter;
import org.zerhusen.security.JwtAccessDeniedHandler;
import org.zerhusen.security.JwtAuthenticationEntryPoint;
import org.zerhusen.security.jwt.JWTConfigurer;
import org.zerhusen.security.jwt.TokenProvider;

@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

   private final TokenProvider tokenProvider;
   private final CorsFilter corsFilter;
   private final JwtAuthenticationEntryPoint authenticationErrorHandler;
   private final JwtAccessDeniedHandler jwtAccessDeniedHandler;

   /**
    * 当前类的构造器, Spring 在初始化bean的时候回将,参数中的依赖注入进来
    * 构造器注入, 再注入的时候必须强制依赖 有这些 Bean, 依照加载顺序, 参数 Bean 会被提前初始化
    * 如果遇到循环依赖就启动失败
    *
    * @param tokenProvider              令牌提供
    * @param corsFilter                 cors 过滤器
    * @param authenticationErrorHandler 身份验证错误处理程序
    * @param jwtAccessDeniedHandler     jwt拒绝访问处理程序
    */
   public WebSecurityConfig(
      TokenProvider tokenProvider,
      CorsFilter corsFilter,
      JwtAuthenticationEntryPoint authenticationErrorHandler,
      JwtAccessDeniedHandler jwtAccessDeniedHandler
   ) {
      this.tokenProvider = tokenProvider;
      this.corsFilter = corsFilter;
      this.authenticationErrorHandler = authenticationErrorHandler;
      this.jwtAccessDeniedHandler = jwtAccessDeniedHandler;
   }

   // Configure BCrypt password encoder =====================================================================

   /**
    * 默认的密码 验证工具了类
    * 提供 rsa 加密验证
    * @return
    */
   @Bean
   public PasswordEncoder passwordEncoder() {
      return new BCryptPasswordEncoder();
   }

   // Configure paths and requests that should be ignored by Spring Security ================================

   /**
    * WebSecurity 配置类
    * @param web
    */
   @Override
   public void configure(WebSecurity web) {
      web.ignoring()
         // 忽略 OPTIONS 的请求, url 过滤规则为所有请求, OPTIONS 是跨域请求的预请求
         // 详细阅读文章: https://developer.mozilla.org/zh-CN/docs/Web/HTTP/Access_control_CORS
         .antMatchers(HttpMethod.OPTIONS, "/**")

         // allow anonymous resource requests
         .antMatchers(
            "/",
            "/*.html",
            "/favicon.ico",
            "/**/*.html",
            "/**/*.css",
            "/**/*.js",
            "/h2-console/**"
         );
   }

   // Configure security settings ===========================================================================

   /**
    * 配置
    *
    * @param httpSecurity http安全性
    * @throws Exception 异常
    */
   @Override
   protected void configure(HttpSecurity httpSecurity) throws Exception {
      httpSecurity
         // we don't need CSRF because our token is invulnerable
         // 关闭 csrf   详细解释: https://baike.baidu.com/item/%E8%B7%A8%E7%AB%99%E8%AF%B7%E6%B1%82%E4%BC%AA%E9%80%A0/13777878?fromtitle=CSRF&fromid=2735433&fr=aladdin
         .csrf().disable()

         // 添加一个拦截器 在 UsernamePasswordAuthenticationFilter 拦截器之前
         // UsernamePasswordAuthenticationFilter 是security 第一个拦截器, 将用户名和密码封装为 UsernamePasswordAuthenticationToken
         // 传递到下一个拦截器中
         .addFilterBefore(corsFilter, UsernamePasswordAuthenticationFilter.class)

         // 异常处理器配置
         .exceptionHandling()
         // 认证失败 说明未登录 返回 401 code
         .authenticationEntryPoint(authenticationErrorHandler)
         // 权限校验失败 就是所说的权限不足 返回 403  code
         .accessDeniedHandler(jwtAccessDeniedHandler)

         // enable h2-console
         .and()
         .headers()
         .frameOptions()
         .sameOrigin()

         // create no session
         .and()
         // session 规则 因为 jwt 每次请求都不会携带 sessionId 所以没有和服务器保持状态的情况, 不需要 session
         .sessionManagement()
         // 永远不会创建 session
         .sessionCreationPolicy(SessionCreationPolicy.STATELESS)

         .and()
         // 请求权限配置
         .authorizeRequests()
         // /api/authenticate 任意皆可访问
         .antMatchers("/api/authenticate").permitAll()
         // .antMatchers("/api/register").permitAll()
         // .antMatchers("/api/activate").permitAll()
         // .antMatchers("/api/account/reset-password/init").permitAll()
         // .antMatchers("/api/account/reset-password/finish").permitAll()

         // api person 需要 User 角色
         .antMatchers("/api/person").hasAuthority("ROLE_USER")
         // 需要 admin 角色
         .antMatchers("/api/hiddenmessage").hasAuthority("ROLE_ADMIN")

         // 剩下未配置请求都需要登录后才可以请求
         .anyRequest().authenticated()

         .and()
         // 这里是一个 SecurityConfigurerAdapter 见名之意 , security config 适配器
         // 主要配置了 jwt filter
         .apply(securityConfigurerAdapter());
   }

   private JWTConfigurer securityConfigurerAdapter() {
      return new JWTConfigurer(tokenProvider);
   }
}
