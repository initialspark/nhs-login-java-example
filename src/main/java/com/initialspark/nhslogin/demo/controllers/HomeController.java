package com.initialspark.nhslogin.demo.controllers;

import com.google.gson.JsonObject;
import org.mitre.openid.connect.model.OIDCAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.util.HashMap;
import java.util.Map;

@Controller
public class HomeController {

    @GetMapping("/")
    public String home() {
        return "home";
    }

    @GetMapping("/user-details")
    public String userDetails(Model model) {
        SecurityContext sc = SecurityContextHolder.getContext();
        OIDCAuthenticationToken auth = (OIDCAuthenticationToken) sc.getAuthentication();

        Map<String, String> userInfoMap = new HashMap<>();
        JsonObject userInfoSource = auth.getUserInfo().getSource();

        for (String keyStr : userInfoSource.keySet()) {
            Object keyValue = userInfoSource.get(keyStr);
            userInfoMap.put(keyStr, keyValue.toString());
        }

        model.addAttribute("userInfoMap", userInfoMap);

        return "userdetails";
    }
}
