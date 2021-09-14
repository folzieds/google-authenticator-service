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
    public String getGoogleOTPCOde(@RequestHeader String secretKey){
        // TODO: Use the username to get the secret key and confirm the otp
        return twoFactorAuthenticationService.getOTP(secretKey);
    }
    @GetMapping("secret")
    public String getSecretKey(){
        return twoFactorAuthenticationService.getSecretKey();
    }

    @GetMapping(value = "generate", produces = MediaType.IMAGE_PNG_VALUE)
    public BufferedImage generateQrCode(@RequestParam("account") String account, @RequestParam("issuer") String issuer) throws WriterException{
        return twoFactorAuthenticationService.generateQr(account, issuer);
    }
}
