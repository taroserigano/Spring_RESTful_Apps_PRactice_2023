package in.bushansirgur.expensetrackerapi.security;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import in.bushansirgur.expensetrackerapi.util.JwtTokenUtil;
import io.jsonwebtoken.ExpiredJwtException;

public class JwtRequestFilter extends OncePerRequestFilter {

	@Autowired
	private JwtTokenUtil jwtTokenUtil;
	
	@Autowired
	private CustomUserDetailsService userDetailsService;
	
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		
		final String requestTokenHeader = request.getHeader("Authorization");
		
		String jwtToken = null;
		String username = null;
		
		if (requestTokenHeader != null && requestTokenHeader.startsWith("Bearer ")) {
			
			jwtToken = requestTokenHeader.substring(7);
			
			try {
				username = jwtTokenUtil.getUsernameFromToken(jwtToken);
			} catch (IllegalArgumentException e) {
				throw new RuntimeException("Unable to get JWT token");
			} catch (ExpiredJwtException e) {
				throw new RuntimeException("Jwt token has expired");
			}
			
		}
		
		//Once we get the token, validate the token
		if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
			
			// extract token 
			UserDetails userDetails = userDetailsService.loadUserByUsername(username);
			
			// validate token by comparing 
			if (jwtTokenUtil.validateToken(jwtToken, userDetails)) {
				
				// generate auth token 
				UsernamePasswordAuthenticationToken authToken = 
						new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
				
				// add the user details
				authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
				
				// store in the context 
				SecurityContextHolder.getContext().setAuthentication(authToken);
				
			}
			
			
		}
		// pass on to the next 
		filterChain.doFilter(request, response);
		
	}

}
























