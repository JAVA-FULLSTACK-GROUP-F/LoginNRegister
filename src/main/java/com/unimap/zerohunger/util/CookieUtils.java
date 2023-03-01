package com.unimap.zerohunger.util;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.Base64;
import java.util.Optional;

import jakarta.servlet.http.HttpServletRequest;

public class CookieUtils implements Serializable{
 
    public static Optional<jakarta.servlet.http.Cookie> getCookie(HttpServletRequest request, String name) {
        jakarta.servlet.http.Cookie[] cookies = request.getCookies();
 
        if (cookies != null && cookies.length > 0) {
            for (jakarta.servlet.http.Cookie cookie : cookies) {
                if (cookie.getName().equals(name)) {
                    return Optional.of(cookie);
                }
            }
        }
 
        return Optional.empty();
    }
 

    public static <T> String serialize(T object) throws IOException {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
             ObjectOutputStream oos = new ObjectOutputStream(baos)) {
            oos.writeObject(object);
            return Base64.getEncoder().encodeToString(baos.toByteArray());
        }}
 
        public static <T> T deserialize(byte[] bytes, Class<T> cls) throws IOException, ClassNotFoundException {
            ByteArrayInputStream bis = new ByteArrayInputStream(bytes);
            ObjectInputStream in = new ObjectInputStream(bis);
            T object = cls.cast(in.readObject());
            in.close();
            return object;
        }
        
    

    public static void deleteCookie(jakarta.servlet.http.HttpServletRequest request,
            jakarta.servlet.http.HttpServletResponse response, String redirectUriParamCookieName) {
    }

    public static void addCookie(jakarta.servlet.http.HttpServletResponse response,
            String oauth2AuthorizationRequestCookieName, String serialize, int cookieexpireseconds) {
    }
}