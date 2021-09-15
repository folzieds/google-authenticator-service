package com.phos.authenticator.service;

/*
 * Created By Folarin
 * on 9/7/2021
 */

import com.google.zxing.WriterException;

import java.awt.image.BufferedImage;

public interface TwoFactorAuthenticationService {

    String getOTP(String username);

    BufferedImage generateQr(String account, String issuer) throws WriterException;

}
