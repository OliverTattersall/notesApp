package com.secure.notes.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

// checks if valid request by checking if it has the header X-Valid-Request
// we have to comment out component otherwise it will automatically insert into filter chain
//@Component
public class RequestValidationFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String header = request.getHeader("X-Valid-Request");
        if (header == null || !header.equals("true")) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid request"); //despite this sending an error 400, this will later be overwritten to 401, but in the logging filter will say 400
            return;
        }
        filterChain.doFilter(request, response);
    }
}
