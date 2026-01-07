package util;

import java.util.Base64;

import static util.PrivateKeyDecryptor.*;

public class SignUtil {
    public static byte[] sign(String certFilePath, String encryptedKeyPath, char[] password, byte[] message) throws Exception {
        PrivateKeyASN1 privateKey = decryptPrivateKey(encryptedKeyPath, password);
        byte[] signedData = signWithSHA256(privateKey, message);

        System.out.println("sign result : " + Base64.getEncoder().encodeToString(signedData));

        verify(certFilePath, message, signedData);

        return signedData;
    }

    public static void verify(String certFilePath, byte[] message, byte[] signature) throws Exception {
        PublicKeyASN1 publicKey = readPublicKeyFromCertificate(certFilePath);
        if (verifyWithSHA256(publicKey, message, signature)) {
            System.out.println("서명 검증 성공");
        } else {
            System.out.println("서명 검증 실패");
        }
    }

//    public static void main(String[] args) throws Exception {
//        System.out.println("SignTest");
//        String certFilePath = "C:\\Dev\\npki-sign-util\\data\\SignCert.der";
//        String encryptedKeyPath = "C:\\Dev\\npki-sign-util\\data\\SignPri.key";
//        String password = "asdfasdf";
//
//        byte[] message = "Hello, World!".getBytes();
//        sign(certFilePath, encryptedKeyPath, password.toCharArray(), message);
//    }
}