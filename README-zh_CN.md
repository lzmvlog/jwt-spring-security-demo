# 阅读前准备 
翻译不易, 麻烦点击一下 Start , Fork , 项目下载下载 , 等待依赖下载完毕, 直接启动,
本项目未对源项目做更新, 只是添加了注释内容 原地址: `https://github.com/szerhusenBC/jwt-spring-security-demo`
谢谢各位大老爷们

注: 启动报错, H2 报错不影响使用: org.hibernate.tool.schema.spi.CommandAcceptanceException: Error executing DDL "# noinspection SqlNoDataSourceInspectionForFile" via JDBC Statement
有兴趣自己可以解决,是 JPA DDL 语句问题

启动程序后打开URL: `http://localhost:8080/h2-console`
![UTOOLS1576923447990.png](https://i.loli.net/2019/12/21/pNEOwjP9dTrYDAz.png)

看到如图
![UTOOLS1576923587201.png](https://i.loli.net/2019/12/21/rdu5aT1DvCFonyE.png)

左侧 有表 `AUTHORITY`, `USER` , `USER_AUTHORITY`
来源于 `org.zerhusen.security.model` 中的 JPA DDL

启动完成后 正式开始, 这里需要一点 security 的基础, 如果没有看过 security , 可以参考我写的这篇博客
Spring Security 初体验: `https://www.runjava.cn/archives/spring-boot-security`

在这开始之前我们需要先知道有几个基本的配置类
`org.zerhusen.config.WebSecurityConfig`  在类中注释我详细会表明配置信息

从 `org.zerhusen.config.WebSecurityConfig` 开始看注释内容吧!

## org.zerhusen.config.WebSecurityConfig 配置类
![UTOOLS1576925667025.png](https://i.loli.net/2019/12/21/koz8Ib6QdS9Leun.png)

```java
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
```

### 添加 Filter

| 这里其实也可以模仿 CorsFilter 拦截器去添加

```java

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
```


## Jwt Filter 配置类
```java
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
```
### Jwt util

```java
@Component
public class TokenProvider implements InitializingBean {

   private final Logger log = LoggerFactory.getLogger(TokenProvider.class);

   private static final String AUTHORITIES_KEY = "auth";

   private final String base64Secret;
   private final long tokenValidityInMilliseconds;
   private final long tokenValidityInMillisecondsForRememberMe;

   private Key key;


   /**
    * @Value 可以从 application 配置中获取到配置信息 注入到参数内
    * @param base64Secret
    * @param tokenValidityInSeconds
    * @param tokenValidityInSecondsForRememberMe
    */
   public TokenProvider(
      @Value("${jwt.base64-secret}") String base64Secret,
      @Value("${jwt.token-validity-in-seconds}") long tokenValidityInSeconds,
      @Value("${jwt.token-validity-in-seconds-for-remember-me}") long tokenValidityInSecondsForRememberMe) {
      this.base64Secret = base64Secret;
      this.tokenValidityInMilliseconds = tokenValidityInSeconds * 1000;
      this.tokenValidityInMillisecondsForRememberMe = tokenValidityInSecondsForRememberMe * 1000;
   }

   @Override
   public void afterPropertiesSet() {
      byte[] keyBytes = Decoders.BASE64.decode(base64Secret);
      this.key = Keys.hmacShaKeyFor(keyBytes);
   }

   public String createToken(Authentication authentication, boolean rememberMe) {
      // 获取到权限集合 拼接转换为 ,
      String authorities = authentication.getAuthorities().stream()
         .map(GrantedAuthority::getAuthority)
         .collect(Collectors.joining(","));

      long now = (new Date()).getTime();
      Date validity;
      // 记住我 true false 只是token 时长不一样 自己配置就好
      if (rememberMe) {
         validity = new Date(now + this.tokenValidityInMillisecondsForRememberMe);
      } else {
         validity = new Date(now + this.tokenValidityInMilliseconds);
      }

      // build jwt
      return Jwts.builder()
         .setSubject(authentication.getName())
         .claim(AUTHORITIES_KEY, authorities)
         .signWith(key, SignatureAlgorithm.HS512)
         .setExpiration(validity)
         .compact();
   }

   public Authentication getAuthentication(String token) {
      // 解析token 获取到主体内容
      Claims claims = Jwts.parser()
         .setSigningKey(key)
         .parseClaimsJws(token)
         .getBody();

      // 将获取到的 权限字符串解密 拼接 map 转换为 SimpleGrantedAuthority 转为一个 List
      Collection<? extends GrantedAuthority> authorities =
         Arrays.stream(claims.get(AUTHORITIES_KEY).toString().split(","))
            .map(SimpleGrantedAuthority::new)
            .collect(Collectors.toList());

      // 构建一个 UserDetails  org.zerhusen.security.UserModelDetailsService 这里返回的 User 对象和  UserModelDetailsService  一样
      User principal = new User(claims.getSubject(), "", authorities);
      // 返回一个 UsernamePasswordAuthenticationToken
      return new UsernamePasswordAuthenticationToken(principal, token, authorities);
   }

   public boolean validateToken(String authToken) {
      try {
         // 解密token 如果不抛出异常 就是成功
         Jwts.parser().setSigningKey(key).parseClaimsJws(authToken);
         return true;
      } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {
         log.info("Invalid JWT signature.");
         log.trace("Invalid JWT signature trace: {}", e);
      } catch (ExpiredJwtException e) {
         log.info("Expired JWT token.");
         log.trace("Expired JWT token trace: {}", e);
      } catch (UnsupportedJwtException e) {
         log.info("Unsupported JWT token.");
         log.trace("Unsupported JWT token trace: {}", e);
      } catch (IllegalArgumentException e) {
         log.info("JWT token compact of handler are invalid.");
         log.trace("JWT token compact of handler are invalid trace: {}", e);
      }
      return false;
   }
}
```

## 最后一步 自定义认证
```java
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

```


最后token 可以通过前段库 jwt-decode.min.js 去解析 payload 部分 就是我们希望去公开的部分
```java
 public class TokenProvider implements InitializingBean {
 
    public String createToken(Authentication authentication, boolean rememberMe) {
    
       // build jwt
       return Jwts.builder()
            // 这里的 就是 payload 部分
          .setSubject(authentication.getName())
          .claim(AUTHORITIES_KEY, authorities)
          .signWith(key, SignatureAlgorithm.HS512)
          .setExpiration(validity)
          .compact();
    }
 
 }
```
然后 这里 配置类 static 文件, 默认为index.html 我们直接打开 `http://localhost:8080/`

测试:
![UTOOLS1576926252260.png](https://i.loli.net/2019/12/21/UaKQ1cLj9YRq2Ak.png)
![UTOOLS1576926274548.png](https://i.loli.net/2019/12/21/zwdTvC8XaxSFtM7.png)
![UTOOLS1576926382192.png](https://i.loli.net/2019/12/21/TCDXLsgF2GfSkmw.png)

前段测试 大家就自己测一下好了.
