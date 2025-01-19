package com.qq.controller;


import com.qq.util.JwtUtil;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author chenlirui
 * @date 2025年01月18日 17:14
 * @description：TODO 登录
 */

@RestController
public class AuthController {

    private final JwtUtil jwtUtil;

    public AuthController(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @PostMapping("/api/auth/login")
    public String login(@RequestParam String username, @RequestParam String password) {
        // Assuming the authentication process is successful, generate JWT
        return jwtUtil.generateToken(username);
    }

    @PostMapping("/api/auth/register")
    public String register(@RequestParam String username, @RequestParam String password) {
        // Assuming the authentication process is successful, generate JWT
        return jwtUtil.generateToken(username);
    }

}
