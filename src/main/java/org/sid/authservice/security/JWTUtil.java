package org.sid.authservice.security;

public class JWTUtil {
    public static final String SECRET = "mySecret1234";
    public static final String AUTH_HEAD = "Authorization";
    public static final String PREFIX = "Bearer ";
    public static final long ACCESS_EXPIRES_AT = 60*60*1000;
    public static final long REFRESH_EXPIRES_AT = 24*60*60*1000;
}
