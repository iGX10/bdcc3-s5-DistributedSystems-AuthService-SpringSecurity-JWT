package org.sid.authservice.security.web;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Data;
import org.sid.authservice.security.JWTUtil;
import org.sid.authservice.security.entities.AppRole;
import org.sid.authservice.security.entities.AppUser;
import org.sid.authservice.security.service.AccountService;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.security.Principal;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
public class AccountRestController {
    private AccountService accountService;

    public AccountRestController(AccountService accountService) {
        this.accountService = accountService;
    }

    @PostAuthorize("hasAuthority('USER')")
    @GetMapping(path = "/users")
    public List<AppUser> getUsers() {
        return accountService.listUsers();
    }

    @PostAuthorize("hasAuthority('ADMIN')")
    @PostMapping(path = "/users")
    public AppUser saveUser(@RequestBody AppUser user) {
        return accountService.addNewUser(user);
    }

    @PostAuthorize("hasAuthority('ADMIN')")
    @PostMapping(path = "/roles")
    public AppRole saveRole(@RequestBody AppRole role) {
        return accountService.addNewRole(role);
    }

    @PostAuthorize("hasAuthority('ADMIN')")
    @PostMapping(path = "/addRoleToUser")
    public void saveRoleToUser(@RequestBody UserRoleForm userRoleForm) {
        accountService.addRoleToUser(userRoleForm.getUsername(), userRoleForm.getRoleName());
    }

    @GetMapping(path = "/refreshToken")
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws Exception{
        String authToken = request.getHeader(JWTUtil.AUTH_HEAD);

        if(authToken!=null && authToken.startsWith(JWTUtil.PREFIX)) {
            try {
                String refreshToken = authToken.substring(JWTUtil.PREFIX.length());
                Algorithm algo = Algorithm.HMAC256(JWTUtil.SECRET);
                JWTVerifier jwtVerifier = JWT.require(algo).build();
                DecodedJWT decodedJWT = jwtVerifier.verify(refreshToken);

                String username = decodedJWT.getSubject();
                AppUser user = accountService.loadUserByUsername(username);

                String accessToken = JWT.create()
                        .withSubject(user.getUsername())
                        .withIssuer(request.getRequestURI())
                        .withExpiresAt(new Date(System.currentTimeMillis()+5*60*1000))
                        .withClaim("roles", user.getRoles().stream().map(r -> r.getName()).collect(Collectors.toList()))
                        .sign(algo);

                Map<String, String> idToken = new HashMap<>();
                idToken.put("access-token", accessToken);
                idToken.put("refresh-token", refreshToken);

                response.setContentType("application/json");
                new ObjectMapper().writeValue(response.getOutputStream(), idToken);
            } catch( Exception e) {
                throw e;
            }
        }
        else {
            throw new RuntimeException("Invalid refresh token !!!!");
        }
    }

    @GetMapping(path = "/profile")
    public AppUser profile(Principal principal) {
        return accountService.loadUserByUsername(principal.getName());
    }
}


@Data
class UserRoleForm {
    private String username;
    private String roleName;
}
