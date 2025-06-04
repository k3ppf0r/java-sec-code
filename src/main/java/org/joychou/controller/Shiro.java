package org.joychou.controller;


import lombok.extern.slf4j.Slf4j;
import org.apache.shiro.crypto.AesCipherService;
import org.joychou.config.Constants;
import org.joychou.util.CookieUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.*;

import static org.springframework.web.util.WebUtils.getCookie;

@Slf4j
@RestController
public class Shiro {
    private static final Logger logger = LoggerFactory.getLogger(SSRF.class);
    byte[] KEYS = java.util.Base64.getDecoder().decode("kPH+bIxk5D2deZiIxcaaaA==");
    private final static String DELETE_ME = "deleteMe";
    AesCipherService acs = new AesCipherService();


    @GetMapping(value = "/shiro/deserialize")
    public String shiro_deserialize(HttpServletRequest req, HttpServletResponse res) {
        Cookie cookie = getCookie(req, Constants.REMEMBER_ME_COOKIE);
        if (null == cookie) {
            return "No rememberMe cookie. Right?";
        }

        try {
            String rememberMe = cookie.getValue();
            byte[] b64DecodeRememberMe = java.util.Base64.getDecoder().decode(rememberMe);
            byte[] aesDecrypt = acs.decrypt(b64DecodeRememberMe, KEYS).getBytes();
            ByteArrayInputStream bytes = new ByteArrayInputStream(aesDecrypt);
            ObjectInputStream in = new ObjectInputStream(bytes);
            in.readObject();
            in.close();
        } catch (Exception e){
            if (CookieUtils.addCookie(res, "rememberMe", DELETE_ME)){
                logger.error(e.getMessage());
                return "RememberMe cookie decrypt error. Set deleteMe cookie success.";
            }
        }

        return "Shiro deserialize";
    }
}
