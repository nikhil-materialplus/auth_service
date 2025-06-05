package com.budgetpulse.auth_service.service;

import com.budgetpulse.auth_service.dto.AuthResponse;
import com.budgetpulse.auth_service.dto.LoginRequest;
import com.budgetpulse.auth_service.exception.InvalidCredentialsException;
import com.budgetpulse.auth_service.model.User;
import com.budgetpulse.auth_service.repository.UserRepository;
import com.budgetpulse.auth_service.security.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final JwtService jwtService;
    // ✅ TODO: Add password encoder for production
    // private final PasswordEncoder passwordEncoder;

    public AuthResponse login(LoginRequest request) {
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new InvalidCredentialsException("Invalid credentials")); // ✅ FIXED: Generic error message

        // ⚠️ WARNING: Plain text password comparison - USE PASSWORD ENCODER IN PRODUCTION!
        if (!user.getPassword().equals(request.getPassword())) {
            throw new InvalidCredentialsException("Invalid credentials");
        }

        // ✅ FIXED: Made role checking optional (remove if not needed)
        if (request.getRole() != null && !user.getRole().equalsIgnoreCase(request.getRole())) {
            throw new InvalidCredentialsException("Invalid credentials");
        }

        String token = jwtService.generateToken(user);
        return new AuthResponse(token, user.getRole());
    }
}
