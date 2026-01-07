package util;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;

public class PrivateKeyDecryptor {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * NPKI(공동인증서) 개인키를 복호화합니다.
     * SEED 암호화 알고리즘을 사용하는 한국 전자서명 표준을 지원합니다.
     * 지원 알고리즘:
     * - 1.2.840.113549.1.5.13 (PKCS5 PBES2)
     * - 1.2.410.200004.1.15 (SEED-CBC-WITH-SHA1)
     * - 1.2.410.200004.1.4 (SEED-CBC)
     */
    public static PrivateKeyASN1 decryptPrivateKey(String encryptedKeyPath, char[] password) {
        try {
            byte[] encodedKey = readFile(encryptedKeyPath);
            byte[] decryptedKey = null;

            // ASN.1 파싱 - EncryptedPrivateKeyInfo 구조
            ASN1Sequence asn1Sequence;
            try (ByteArrayInputStream bIn = new ByteArrayInputStream(encodedKey);
                 ASN1InputStream aIn = new ASN1InputStream(bIn)) {
                ASN1Primitive primitive = aIn.readObject();

                if (primitive == null) {
                    throw new IllegalArgumentException("Failed to read ASN.1 object from file");
                }

                asn1Sequence = ASN1Sequence.getInstance(primitive);
            }

            if (asn1Sequence.size() < 2) {
                throw new IllegalArgumentException("Invalid EncryptedPrivateKeyInfo structure");
            }

            // AlgorithmIdentifier와 암호화된 데이터 추출
            AlgorithmIdentifier algId = AlgorithmIdentifier.getInstance(asn1Sequence.getObjectAt(0));

            // 두 번째 요소를 OCTET STRING으로 파싱
            ASN1Primitive dataObject = asn1Sequence.getObjectAt(1).toASN1Primitive();
            org.bouncycastle.asn1.ASN1OctetString data;

            if (dataObject instanceof org.bouncycastle.asn1.ASN1OctetString) {
                data = (org.bouncycastle.asn1.ASN1OctetString) dataObject;
            } else {
                throw new IllegalArgumentException("Second element is not OCTET STRING, tag: " + dataObject.getClass().getSimpleName());
            }

            String algorithmOid = algId.getAlgorithm().getId();

            if ("1.2.840.113549.1.5.13".equals(algorithmOid)) {
                // PKCS5 PBES2 방식
                decryptedKey = decryptPKCS5PBES2(algId, data, new String(password));

            } else if ("1.2.410.200004.1.15".equals(algorithmOid)) {
                // SEED-CBC-WITH-SHA1 방식
                decryptedKey = decryptSeedCbcWithSha1(algId, data, new String(password));

            } else if ("1.2.410.200004.1.4".equals(algorithmOid)) {
                // SEED-CBC 방식 (고정 IV)
                decryptedKey = decryptSeedCbc(algId, data, new String(password));

            } else {
                throw new IllegalArgumentException("Unsupported encryption algorithm: " + algorithmOid);
            }

            // 복호화된 PKCS#8 데이터를 PrivateKeyASN1로 변환
            return PrivateKeyASN1.fromPkcs8Der(decryptedKey);

        } catch (Exception e) {
            throw new RuntimeException("Failed to decrypt NPKI private key: " + e.getMessage(), e);
        }
    }

    /**
     * PKCS5 PBES2 방식 복호화 (1.2.840.113549.1.5.13)
     */
    private static byte[] decryptPKCS5PBES2(AlgorithmIdentifier algId,
                                            org.bouncycastle.asn1.ASN1OctetString data,
                                            String password) throws Exception {
        // PBES2 파라미터 파싱
        ASN1Sequence pbes2Params = (ASN1Sequence) algId.getParameters();

        // Key Derivation Function (KDF) 파라미터
        ASN1Sequence kdfSeq = (ASN1Sequence) pbes2Params.getObjectAt(0);
        ASN1Sequence pbkdf2Params = (ASN1Sequence) kdfSeq.getObjectAt(1);

        // Salt 추출
        org.bouncycastle.asn1.DEROctetString saltOctet =
                (org.bouncycastle.asn1.DEROctetString) pbkdf2Params.getObjectAt(0);
        byte[] salt = saltOctet.getOctets();

        // Iteration Count 추출
        org.bouncycastle.asn1.ASN1Integer iterationCount =
                (org.bouncycastle.asn1.ASN1Integer) pbkdf2Params.getObjectAt(1);
        int iterations = iterationCount.getValue().intValue();

        // Encryption Scheme 파라미터
        ASN1Sequence encScheme = (ASN1Sequence) pbes2Params.getObjectAt(1);

        // IV 추출
        org.bouncycastle.asn1.DEROctetString ivOctet =
                (org.bouncycastle.asn1.DEROctetString) encScheme.getObjectAt(1);
        byte[] iv = ivOctet.getOctets();

        // PBKDF2로 키 생성
        int keySize = 256;
        org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator generator =
                new org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator();
        generator.init(
                org.bouncycastle.crypto.PBEParametersGenerator.PKCS5PasswordToBytes(password.toCharArray()),
                salt,
                iterations
        );

        org.bouncycastle.crypto.params.KeyParameter keyParam =
                (org.bouncycastle.crypto.params.KeyParameter) generator.generateDerivedParameters(keySize);

        // SEED 복호화
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        SecretKeySpec secretKey = new SecretKeySpec(keyParam.getKey(), "SEED");

        Cipher cipher = Cipher.getInstance("SEED/CBC/PKCS5Padding", "BC");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);

        return cipher.doFinal(data.getOctets());
    }

    /**
     * SEED-CBC-WITH-SHA1 방식 복호화 (1.2.410.200004.1.15)
     */
    private static byte[] decryptSeedCbcWithSha1(AlgorithmIdentifier algId,
                                                 org.bouncycastle.asn1.ASN1OctetString data,
                                                 String password) throws Exception {
        ASN1Sequence params = (ASN1Sequence) algId.getParameters();

        // Salt 추출
        org.bouncycastle.asn1.DEROctetString saltOctet =
                (org.bouncycastle.asn1.DEROctetString) params.getObjectAt(0);
        byte[] salt = saltOctet.getOctets();

        // Iteration Count 추출
        org.bouncycastle.asn1.ASN1Integer iterationCount =
                (org.bouncycastle.asn1.ASN1Integer) params.getObjectAt(1);
        int iterations = iterationCount.getValue().intValue();

        // SHA-1 기반 키 유도
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        md.update(password.getBytes());
        md.update(salt);
        byte[] dk = md.digest();

        for (int i = 1; i < iterations; i++) {
            dk = md.digest(dk);
        }

        // 키 데이터 추출 (첫 16바이트)
        byte[] keyData = new byte[16];
        System.arraycopy(dk, 0, keyData, 0, 16);

        // Digest 바이트 추출 (마지막 4바이트)
        byte[] digestBytes = new byte[4];
        System.arraycopy(dk, 16, digestBytes, 0, 4);

        // IV 생성
        MessageDigest digest = MessageDigest.getInstance("SHA-1");
        digest.reset();
        digest.update(digestBytes);
        byte[] divHash = digest.digest();

        byte[] iv = new byte[16];
        System.arraycopy(divHash, 0, iv, 0, 16);

        // SEED 복호화
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        SecretKeySpec secretKey = new SecretKeySpec(keyData, "SEED");

        Cipher cipher = Cipher.getInstance("SEED/CBC/PKCS5Padding", "BC");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);

        return cipher.doFinal(data.getOctets());
    }

    /**
     * SEED-CBC 방식 복호화 (1.2.410.200004.1.4) - 고정 IV 사용
     */
    private static byte[] decryptSeedCbc(AlgorithmIdentifier algId,
                                         org.bouncycastle.asn1.ASN1OctetString data,
                                         String password) throws Exception {
        ASN1Sequence params = (ASN1Sequence) algId.getParameters();

        // Salt 추출
        org.bouncycastle.asn1.DEROctetString saltOctet =
                (org.bouncycastle.asn1.DEROctetString) params.getObjectAt(0);
        byte[] salt = saltOctet.getOctets();

        // Iteration Count 추출
        org.bouncycastle.asn1.ASN1Integer iterationCount =
                (org.bouncycastle.asn1.ASN1Integer) params.getObjectAt(1);
        int iterations = iterationCount.getValue().intValue();

        // SHA-1 기반 키 유도
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        md.update(password.getBytes());
        md.update(salt);
        byte[] dk = md.digest();

        for (int i = 1; i < iterations; i++) {
            dk = md.digest(dk);
        }

        // 키 데이터 추출 (첫 16바이트)
        byte[] keyData = new byte[16];
        System.arraycopy(dk, 0, keyData, 0, 16);

        // 고정 IV 사용
        byte[] iv = "012345678912345".getBytes();

        // SEED 복호화
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        SecretKeySpec secretKey = new SecretKeySpec(keyData, "SEED");

        Cipher cipher = Cipher.getInstance("SEED/CBC/PKCS5Padding", "BC");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);

        return cipher.doFinal(data.getOctets());
    }

    /**
     * 개인키로 메시지에 SHA-256 서명을 생성합니다.
     */
    public static byte[] signWithSHA256(PrivateKeyASN1 privateKey, byte[] message) throws Exception {
        String algorithm = privateKey.getAlgorithm();

        if ("RSA".equals(algorithm)) {
            return signRSA(privateKey, message);
        } else if ("DSA".equals(algorithm)) {
            return signDSA(privateKey, message);
        } else if ("EC".equals(algorithm)) {
            return signECDSA(privateKey, message);
        } else {
            throw new UnsupportedOperationException("Unsupported algorithm: " + algorithm);
        }
    }

    /**
     * RSA 서명 생성
     */
    private static byte[] signRSA(PrivateKeyASN1 privateKey, byte[] message) throws Exception {
        // SHA-256 해시 계산
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hash = md.digest(message);

        // RSA 개인키 파라미터 추출
        BigInteger n = privateKey.getY();  // modulus
        BigInteger d = privateKey.getX();  // private exponent

        // PKCS#1 v1.5 패딩 적용
        byte[] paddedHash = applyPKCS1Padding(hash, n.bitLength() / 8);

        // RSA 서명: s = m^d mod n
        BigInteger m = new BigInteger(1, paddedHash);
        BigInteger signature = m.modPow(d, n);

        return signature.toByteArray();
    }

    /**
     * DSA 서명 생성
     */
    private static byte[] signDSA(PrivateKeyASN1 privateKey, byte[] message) throws Exception {
        // JCA Signature 사용
        KeyFactory keyFactory = KeyFactory.getInstance("DSA", "BC");
        PrivateKey jcaKey = keyFactory.generatePrivate(
                new PKCS8EncodedKeySpec(privateKey.getEncoded())
        );

        Signature signature = Signature.getInstance("SHA256withDSA", "BC");
        signature.initSign(jcaKey);
        signature.update(message);

        return signature.sign();
    }

    /**
     * ECDSA 서명 생성
     */
    private static byte[] signECDSA(PrivateKeyASN1 privateKey, byte[] message) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("ECDSA", "BC");
        PrivateKey jcaKey = keyFactory.generatePrivate(
                new PKCS8EncodedKeySpec(privateKey.getEncoded())
        );

        Signature signature = Signature.getInstance("SHA256withECDSA", "BC");
        signature.initSign(jcaKey);
        signature.update(message);

        return signature.sign();
    }

    /**
     * 공개키로 SHA-256 서명을 검증합니다.
     */
    public static boolean verifyWithSHA256(PublicKeyASN1 publicKey, byte[] message, byte[] signature) {
        try {
            String algorithm = publicKey.getAlgorithm();

            if ("RSA".equals(algorithm)) {
                return verifyRSA(publicKey, message, signature);
            } else if ("DSA".equals(algorithm)) {
                return verifyDSA(publicKey, message, signature);
            } else if ("EC".equals(algorithm)) {
                return verifyECDSA(publicKey, message, signature);
            } else {
                throw new UnsupportedOperationException("Unsupported algorithm: " + algorithm);
            }
        } catch (Exception e) {
            System.err.println("Signature verification failed: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }

    /**
     * RSA 서명 검증
     */
    private static boolean verifyRSA(PublicKeyASN1 publicKey, byte[] message, byte[] signature) throws Exception {
        // 방법 1: JCA Signature 사용 (권장)
        try {
            PublicKey jcaKey = publicKey.toJcaPublicKey("BC");
            Signature verifier = Signature.getInstance("SHA256withRSA", "BC");
            verifier.initVerify(jcaKey);
            verifier.update(message);
            return verifier.verify(signature);
        } catch (Exception e) {
            System.err.println("JCA verification failed, trying manual verification: " + e.getMessage());
        }

        // 방법 2: 수동 검증 (fallback)
        return verifyRSAManual(publicKey, message, signature);
    }

    /**
     * RSA 서명 수동 검증 (디버깅용)
     */
    private static boolean verifyRSAManual(PublicKeyASN1 publicKey, byte[] message, byte[] signature) throws Exception {
        // SHA-256 해시 계산
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hash = md.digest(message);

        // RSA 공개키 파라미터
        BigInteger n = publicKey.getY();  // modulus
        BigInteger e = publicKey.getG();  // public exponent

        // 서명을 BigInteger로 변환 (양수로 처리)
        BigInteger s = new BigInteger(1, signature);

        // 서명 검증: m = s^e mod n
        BigInteger m = s.modPow(e, n);

        // BigInteger를 바이트 배열로 변환 (고정 길이)
        int keySize = (n.bitLength() + 7) / 8;
        byte[] decryptedPadded = m.toByteArray();

        // BigInteger.toByteArray()는 부호 비트를 위해 앞에 0x00을 추가할 수 있음
        if (decryptedPadded.length > keySize) {
            if (decryptedPadded[0] == 0 && decryptedPadded.length == keySize + 1) {
                decryptedPadded = Arrays.copyOfRange(decryptedPadded, 1, decryptedPadded.length);
            }
        }

        // 길이가 부족하면 앞에 0 패딩
        if (decryptedPadded.length < keySize) {
            byte[] padded = new byte[keySize];
            System.arraycopy(decryptedPadded, 0, padded, keySize - decryptedPadded.length, decryptedPadded.length);
            decryptedPadded = padded;
        }

        try {
            // PKCS#1 패딩 제거 및 해시 추출
            byte[] extractedHash = removePKCS1Padding(decryptedPadded);

            // 해시 비교
            return MessageDigest.isEqual(hash, extractedHash);
        } catch (Exception ex) {
            System.err.println("Failed to extract hash from signature: " + ex.getMessage());
            return false;
        }
    }

    /**
     * DSA 서명 검증
     */
    private static boolean verifyDSA(PublicKeyASN1 publicKey, byte[] message, byte[] signature) throws Exception {
        PublicKey jcaKey = publicKey.toJcaPublicKey("BC");

        Signature verifier = Signature.getInstance("SHA256withDSA", "BC");
        verifier.initVerify(jcaKey);
        verifier.update(message);

        return verifier.verify(signature);
    }

    /**
     * ECDSA 서명 검증
     */
    private static boolean verifyECDSA(PublicKeyASN1 publicKey, byte[] message, byte[] signature) throws Exception {
        PublicKey jcaKey = publicKey.toJcaPublicKey("BC");

        Signature verifier = Signature.getInstance("SHA256withECDSA", "BC");
        verifier.initVerify(jcaKey);
        verifier.update(message);

        return verifier.verify(signature);
    }

    /**
     * 인증서 파일에서 공개키를 추출합니다.
     * DER 또는 PEM 형식의 X.509 인증서를 지원합니다.
     */
    public static PublicKeyASN1 readPublicKeyFromCertificate(String certFilePath) throws Exception {
        byte[] certData = readFile(certFilePath);

        // PEM 형식인 경우 DER로 변환
        if (isPemFormat(certData)) {
            certData = pemToDer(certData);
        }

        // X.509 인증서 파싱
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(
                new ByteArrayInputStream(certData)
        );

        // 공개키 추출
        PublicKey jcaPublicKey = cert.getPublicKey();
        byte[] spkiDer = jcaPublicKey.getEncoded();

        return PublicKeyASN1.fromX509SpkiDer(spkiDer);
    }

    /**
     * 파일을 읽어서 바이트 배열로 반환합니다.
     */
    private static byte[] readFile(String filePath) throws Exception {
        try (FileInputStream fis = new FileInputStream(filePath)) {
            byte[] data = new byte[fis.available()];
            fis.read(data);
            return data;
        }
    }

    /**
     * ASN.1 구조 디버깅용 메서드
     */
    public static void debugASN1Structure(String filePath) throws Exception {
        byte[] data = readFile(filePath);

        try (ByteArrayInputStream bIn = new ByteArrayInputStream(data);
             ASN1InputStream aIn = new ASN1InputStream(bIn)) {

            ASN1Primitive primitive = aIn.readObject();
            System.out.println("Root type: " + primitive.getClass().getSimpleName());

            if (primitive instanceof ASN1Sequence) {
                ASN1Sequence seq = (ASN1Sequence) primitive;
                System.out.println("Sequence size: " + seq.size());

                for (int i = 0; i < seq.size(); i++) {
                    ASN1Primitive elem = seq.getObjectAt(i).toASN1Primitive();
                    System.out.println("  [" + i + "] Type: " + elem.getClass().getSimpleName() +
                            ", Tag: " + elem.getClass().getName());

                    if (i == 0 && elem instanceof ASN1Sequence) {
                        ASN1Sequence algSeq = (ASN1Sequence) elem;
                        if (algSeq.size() > 0) {
                            AlgorithmIdentifier algId = AlgorithmIdentifier.getInstance(algSeq);
                            System.out.println("      Algorithm OID: " + algId.getAlgorithm().getId());
                        }
                    }
                }
            }
        }
    }

    // ========== Utility Methods ==========

    /**
     * PKCS#1 v1.5 패딩 적용 (SHA-256용)
     */
    private static byte[] applyPKCS1Padding(byte[] hash, int targetLength) {
        // DigestInfo for SHA-256
        byte[] digestInfo = new byte[] {
                0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, (byte) 0x86,
                0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
                0x00, 0x04, 0x20
        };

        int tLen = digestInfo.length + hash.length;
        int psLen = targetLength - tLen - 3;

        if (psLen < 8) {
            throw new IllegalArgumentException("Key too short for SHA-256 signature");
        }

        byte[] padded = new byte[targetLength];
        padded[0] = 0x00;
        padded[1] = 0x01;
        Arrays.fill(padded, 2, 2 + psLen, (byte) 0xFF);
        padded[2 + psLen] = 0x00;
        System.arraycopy(digestInfo, 0, padded, 3 + psLen, digestInfo.length);
        System.arraycopy(hash, 0, padded, 3 + psLen + digestInfo.length, hash.length);

        return padded;
    }

    /**
     * PKCS#1 v1.5 패딩 제거 및 DigestInfo에서 해시 추출
     */
    private static byte[] removePKCS1Padding(byte[] padded) {
        int i = 0;

        // 0x00 0x01 확인
        if (padded.length < 11 || padded[i++] != 0x00 || padded[i++] != 0x01) {
            throw new IllegalArgumentException("Invalid PKCS#1 padding header");
        }

        // 0xFF 패딩 스킵
        while (i < padded.length && padded[i] == (byte) 0xFF) {
            i++;
        }

        // 0x00 구분자 확인
        if (i >= padded.length || padded[i++] != 0x00) {
            throw new IllegalArgumentException("Invalid PKCS#1 padding separator");
        }

        // 남은 데이터 = DigestInfo + Hash
        byte[] digestInfo = Arrays.copyOfRange(padded, i, padded.length);

        // DigestInfo 구조 확인 및 해시만 추출
        // DigestInfo ::= SEQUENCE {
        //   digestAlgorithm AlgorithmIdentifier,
        //   digest OCTET STRING
        // }

        // SHA-256 DigestInfo는 총 51바이트 (19바이트 헤더 + 32바이트 해시)
        if (digestInfo.length >= 51 && digestInfo[0] == 0x30) {
            // SEQUENCE 내에서 OCTET STRING(0x04) 찾기
            for (int j = 0; j < digestInfo.length - 34; j++) {
                if (digestInfo[j] == 0x04 && digestInfo[j + 1] == 0x20) { // OCTET STRING, length 32
                    return Arrays.copyOfRange(digestInfo, j + 2, j + 34);
                }
            }
        }

        // DigestInfo 전체를 반환하거나, 마지막 32바이트를 해시로 간주
        if (digestInfo.length >= 32) {
            return Arrays.copyOfRange(digestInfo, digestInfo.length - 32, digestInfo.length);
        }

        throw new IllegalArgumentException("Cannot extract hash from DigestInfo");
    }

    /**
     * PEM 형식 여부 확인
     */
    private static boolean isPemFormat(byte[] data) {
        String header = new String(data, 0, Math.min(data.length, 100));
        return header.contains("-----BEGIN");
    }

    /**
     * PEM을 DER로 변환
     */
    private static byte[] pemToDer(byte[] pemData) {
        String pem = new String(pemData);
        pem = pem.replaceAll("-----BEGIN [^-]+-----", "");
        pem = pem.replaceAll("-----END [^-]+-----", "");
        pem = pem.replaceAll("\\s", "");

        return java.util.Base64.getDecoder().decode(pem);
    }
}