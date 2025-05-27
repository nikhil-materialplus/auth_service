package com.budgetpulse.auth_service.controller;
import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpStatus;

import com.budgetpulse.auth_service.dto.AuthResponse;
import com.budgetpulse.auth_service.dto.LoginRequest;
import com.budgetpulse.auth_service.dto.SignupRequest;
import com.budgetpulse.auth_service.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/signup")
    public ResponseEntity<AuthResponse> signup(@RequestBody SignupRequest request) {
        return ResponseEntity.ok(authService.signup(request));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@RequestBody LoginRequest request) {
        return ResponseEntity.ok(authService.login(request));
    }
}
