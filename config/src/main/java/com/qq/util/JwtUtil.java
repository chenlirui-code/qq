package com.qq.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Date;

/**
 * @author chenlirui
 * @date 2025年01月18日 17:10
 * @description：JWT 工具类，提供生成、解析、验证 JWT token 的方法
 */
@Component
public class JwtUtil {

    @Value("${jwt.secret}")
    private String secretKey;


    @Value("${jwt.expiration}")
    private long expirationTime;

    /**
     * 生成 JWT token
     *
     * @param username 用户名（作为 JWT 的 subject）
     * @return 生成的 JWT token
     */
    public String generateToken(String username) {
        return Jwts.builder()
                .setSubject(username) // 设置 JWT 的 subject 为用户名
                .setIssuedAt(new Date()) // 设置 token 的生成时间
                .setExpiration(new Date(System.currentTimeMillis() + expirationTime)) // 设置 token 的过期时间
                .signWith(SignatureAlgorithm.HS256, secretKey) // 使用 HS256 算法和密钥进行签名
                .compact(); // 构建 JWT token
    }

    /**
     * 解析 JWT token，提取出其 claims（声明）
     *
     * @param token JWT token
     * @return Claims 包含 token 中的所有声明
     */
    public Claims extractClaims(String token) {
        // 创建解析器实例，设置签名的密钥
        JwtParser parser = Jwts.parserBuilder()
                .setSigningKey(secretKey) // 设置签名的密钥
                .build(); // 创建解析器
        return parser.parseClaimsJws(token) // 解析 JWT，获取 claims
                .getBody(); // 获取 JWT 中的 claims 部分
    }


    /**
     * 从 JWT token 中提取用户名（subject）
     *
     * @param token JWT token
     * @return token 中的用户名（subject）
     */
    public String extractUsername(String token) {
        return extractClaims(token).getSubject(); // 从 claims 中提取用户名
    }

    /**
     * 验证 JWT token 是否过期
     *
     * @param token JWT token
     * @return true 如果 token 已过期；false 如果 token 尚未过期
     */
    public boolean isTokenExpired(String token) {
        // 获取 token 中的过期时间并与当前时间对比
        return extractClaims(token).getExpiration().before(new Date());
    }

    /**
     * 验证 JWT token 是否有效
     *
     * @param token    JWT token
     * @param username 用户名
     * @return true 如果 token 是有效的；false 如果 token 无效
     */
    public boolean validateToken(String token, String username) {
        // 验证 token 中的用户名是否匹配且 token 是否未过期
        return (username.equals(extractUsername(token)) && !isTokenExpired(token));
    }
}
