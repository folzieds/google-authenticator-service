package com.phos.authenticator.service;

/*
 * Created By Folarin
 * on 9/7/2021
 */

import com.google.zxing.BarcodeFormat;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import de.taimos.totp.TOTP;
import org.apache.commons.codec.binary.Base32;
import org.apache.commons.codec.binary.Hex;
import org.springframework.stereotype.Service;

import java.awt.image.BufferedImage;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.SecureRandom;

@Service
public class TwoFactorAuthenticationServiceImpl implements TwoFactorAuthenticationService{

    // this is the secret key that would be used in the authenticator app
    private String generateSecretKey(){
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[20];

        random.nextBytes(bytes);
        Base32 base32 = new Base32();
        return base32.encodeToString(bytes);
    }

    // the code that is meant to be generated per time
    private String getTOTPCode(String secretKey){
        Base32 base32 = new Base32();
        byte[] bytes = base32.decode(secretKey);
        String hexKey = Hex.encodeHexString(bytes);

        return TOTP.getOTP(hexKey);
    }


    @Override
    public String getOTP(String secretKey) {
        return getTOTPCode(secretKey);

    }

    @Override
    public String getSecretKey() {
        return generateSecretKey();
    }

    @Override
    public BufferedImage generateQr(String account, String issuer) throws WriterException {
        String key = generateSecretKey();
        String link =  getGoogleBarCode(key, account, issuer);
        return generateBarCode(link);
    }

    // secret key is gotten from the method
    private String getGoogleBarCode(String secretKey, String account, String issuer){
        try{
            return "otpauth://totp/" + URLEncoder.encode(issuer + ":" + account, "UTF-8").replace("+","%20")
                    + "?secret=" + URLEncoder.encode(secretKey, "UTF-8");
        }catch (UnsupportedEncodingException ex){
            throw new IllegalStateException(ex);
        }
    }

    private BufferedImage generateBarCode(String link) throws WriterException{
        QRCodeWriter qrCodeWriter = new QRCodeWriter();

        BitMatrix bitMatrix = qrCodeWriter.encode(link, BarcodeFormat.QR_CODE, 200, 200);

        return MatrixToImageWriter.toBufferedImage(bitMatrix);

    }
}
