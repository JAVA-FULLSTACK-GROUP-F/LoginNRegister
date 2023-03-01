package com.unimap.zerohunger.security.oauth2.user;

import java.util.Map;
 
import com.unimap.zerohunger.dto.SocialProvider;
import com.unimap.zerohunger.exception.OAuth2AuthenticationProcessingException;
import com.unimap.zerohunger.security.oauth2.OAuth2UserInfo;
 
public class OAuth2UserInfoFactory {
    public static OAuth2UserInfo getOAuth2UserInfo(String registrationId, Map<String, Object> attributes) {
        if (registrationId.equalsIgnoreCase(SocialProvider.GOOGLE.getProviderType())) {
            return new GoogleOAuth2UserInfo(attributes);
        }  else {
            throw new OAuth2AuthenticationProcessingException("Sorry! Login with " + registrationId + " is not supported yet.");
        }
    }
}
