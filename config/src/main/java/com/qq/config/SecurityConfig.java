package com.qq.config;


import com.qq.filter.JwtAuthenticationFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;


/**
 * @author chenlirui
 * @date 2025年01月18日 17:11
 * @description：TODO 配置 JWT 过滤器来验证 JWT token
 */

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    // 构造函数注入 JwtAuthenticationFilter
    public SecurityConfig(JwtAuthenticationFilter jwtAuthenticationFilter) {
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
    }

    // 配置 HttpSecurity 来设定 URL 权限以及过滤器
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http.csrf().disable()
                .authorizeRequests()
                .antMatchers("/api/auth/login", "/api/auth/register").permitAll()  // login 和 register 端点对所有人开放
                .anyRequest().authenticated()
                .and()
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)  // 将 JwtAuthenticationFilter 添加到过滤链中
                .build();
    }

    // 如果你有自定义的用户服务，可以在此注入
    @Bean
    public UserDetailsService userDetailsService() {
        return username -> {
            // 这里自定义查找用户的逻辑，可以从数据库中查找
            // 这里只是一个示例，正常情况下要根据用户名查找真实用户
            if ("user".equals(username)) {
                return User.builder()
                        .username("user")
                        .password("{noop}password") // 请使用实际加密的密码
                        .roles("USER")
                        .build();
            } else {
                throw new UsernameNotFoundException("用户未找到");
            }
        };
    }
}
