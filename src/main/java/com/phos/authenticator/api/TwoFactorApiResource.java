package com.phos.authenticator.api;
/*
 * Created By Folarin
 * on 9/7/2021
 */

import com.google.zxing.WriterException;
import com.phos.authenticator.service.TwoFactorAuthenticationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;

import java.awt.image.BufferedImage;

@RestController
@RequestMapping("api/v1/otpCode")
public class TwoFactorApiResource {

    @Autowired
    private TwoFactorAuthenticationService twoFactorAuthenticationService;

    @GetMapping("")
    public String getGoogleOTPCOde(@RequestParam String username){
        return twoFactorAuthenticationService.getOTP(username);
    }

    @GetMapping(value = "generate", produces = MediaType.IMAGE_PNG_VALUE)
    public BufferedImage generateQrCode(@RequestParam("username") String username, @RequestParam("issuer") String issuer) throws WriterException{
        return twoFactorAuthenticationService.generateQr(username, issuer);
    }
}
