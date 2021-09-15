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
import lombok.AllArgsConstructor;
import lombok.Getter;
import org.apache.commons.codec.binary.Base32;
import org.apache.commons.codec.binary.Hex;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.http.converter.BufferedImageHttpMessageConverter;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Service;

import java.awt.image.BufferedImage;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.SecureRandom;
import java.sql.ResultSet;
import java.sql.SQLException;

@Service
public class TwoFactorAuthenticationServiceImpl implements TwoFactorAuthenticationService{

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Value("${schema.decrypt.key}")
    private String aesKey;

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
    public String getOTP(String username) {
        String secretKey = getSecretKey(username);
        return getTOTPCode(secretKey);

    }

    public String getSecretKey(String username) {
        String query = String.format("select username, AES_DECRYPT(from_base64(secret_key), '%s') as secret_key, issuer from authenticate_user where username = '%s'",aesKey,username);
        QRData data = jdbcTemplate.queryForObject(query, new QRDataMapper());

        return data != null ? data.getKey(): "";
    }

    @Override
    public BufferedImage generateQr(String username, String issuer) throws WriterException {
        String key = generateSecretKey();
        QRData data = new QRData(issuer,username, key);
        String link =  getGoogleBarCode(data);

        saveUserDetails(username, key, issuer);

        return generateBarCode(link);
    }

    private void saveUserDetails(String username, String key, String issuer) {
        String query = String.format("insert into authenticate_user (username, secret_key, issuer) values ('%s',to_base64(AES_ENCRYPT('%s','%s')), '%s')", username,key,aesKey, issuer);
        jdbcTemplate.execute(query);
    }


    private String getGoogleBarCode(QRData data){
        try{
            return "otpauth://totp/" + URLEncoder.encode(data.getIssuer() + ":" + data.getUsername(), "UTF-8").replace("+","%20")
                    + "?secret=" + URLEncoder.encode(data.getKey(), "UTF-8").replace("+","%20")
                    + "&issuer=" + URLEncoder.encode(data.getIssuer(), "UTF-8").replace("+","%20");
        }catch (UnsupportedEncodingException ex){
            throw new IllegalStateException(ex);
        }
    }

    private BufferedImage generateBarCode(String link) throws WriterException{
        QRCodeWriter qrCodeWriter = new QRCodeWriter();

        BitMatrix bitMatrix = qrCodeWriter.encode(link, BarcodeFormat.QR_CODE, 200, 200);

        return MatrixToImageWriter.toBufferedImage(bitMatrix);

    }

    @Bean
    public HttpMessageConverter<BufferedImage> createImageHttpMessageConverter() {
        return new BufferedImageHttpMessageConverter();
    }

    @AllArgsConstructor
    @Getter
    private class QRData {
        private String issuer;
        private String username;
        private String key;
    }

    private class QRDataMapper implements RowMapper<QRData>{

        @Override
        public QRData mapRow(ResultSet rs, int rowNum) throws SQLException {
            String issuer = rs.getString("issuer");
            String username = rs.getString("username");
            String key = rs.getString("secret_key");
            return new QRData(issuer, username, key);
        }
    }
}
