package util;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DSAParameter;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

public class PublicKeyASN1 implements PublicKey {
    private static final long serialVersionUID = 1L;

    private BigInteger p;
    private BigInteger q;
    private BigInteger g;
    private BigInteger y;
    private byte[] encoded;

    // 파싱한 키 알고리즘 (PrivateKeyInfo의 algorithm OID)
    private String keyAlgorithmOid;
    private String keyAlgorithmName;

    public PublicKeyASN1(BigInteger p, BigInteger q, BigInteger g, BigInteger y) {
        this.p = p;
        this.q = q;
        this.g = g;
        this.y = y;
    }

    // ---- parse from SubjectPublicKeyInfo(ASN1) ----
    public PublicKeyASN1(ASN1Sequence spkiSeq) throws Exception {
        if (spkiSeq == null) throw new IllegalArgumentException("spkiSeq is null");

        this.encoded = spkiSeq.getEncoded(ASN1Encoding.DER);

        SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(spkiSeq);
        AlgorithmIdentifier algId = spki.getAlgorithm();
        this.keyAlgorithmOid = algId.getAlgorithm().getId();

        if ("1.2.840.113549.1.1.1".equals(this.keyAlgorithmOid)) {
            this.keyAlgorithmName = "RSA";
            // subjectPublicKey: BIT STRING -> RSAPublicKey SEQUENCE
            ASN1Primitive pub = ASN1Primitive.fromByteArray(spki.getPublicKeyData().getBytes());
            ASN1Sequence rsaSeq = ASN1Sequence.getInstance(pub);
            RSAPublicKey rsa = RSAPublicKey.getInstance(rsaSeq);

            this.y = rsa.getModulus();        // n
            this.g = rsa.getPublicExponent(); // e

        } else if ("1.2.840.10040.4.1".equals(this.keyAlgorithmOid)) {
            this.keyAlgorithmName = "DSA";

            ASN1Encodable params = algId.getParameters();
            if (params != null && !(params instanceof ASN1Null)) {
                DSAParameter dsaParams = DSAParameter.getInstance(params);
                this.p = dsaParams.getP();
                this.q = dsaParams.getQ();
                this.g = dsaParams.getG();
            }

            ASN1Primitive pub = ASN1Primitive.fromByteArray(spki.getPublicKeyData().getBytes());
            this.y = ASN1Integer.getInstance(pub).getValue();

        } else {
            this.keyAlgorithmName = this.keyAlgorithmOid; // unknown
            // 필요하면 여기서 EC 등 확장
        }
    }

    // (선택) 이 객체를 JCA PublicKey로 다시 뽑고 싶을 때
    public PublicKey toJcaPublicKey(String providerOrNull) throws Exception {
        if (this.encoded == null) throw new IllegalStateException("encoded is null");

        String alg;
        if ("RSA".equals(this.keyAlgorithmName)) alg = "RSA";
        else if ("DSA".equals(this.keyAlgorithmName)) alg = "DSA";
        else alg = "RSA"; // 필요시 조정

        KeyFactory kf = (providerOrNull == null)
                ? KeyFactory.getInstance(alg)
                : KeyFactory.getInstance(alg, providerOrNull);

        return kf.generatePublic(new X509EncodedKeySpec(this.encoded));
    }

    // DER(SubjectPublicKeyInfo)에서 바로 생성
    public static PublicKeyASN1 fromX509SpkiDer(byte[] spkiDer) throws Exception {
        ASN1InputStream aIn = null;
        try {
            aIn = new ASN1InputStream(new ByteArrayInputStream(spkiDer));
            ASN1Primitive p = aIn.readObject();
            return new PublicKeyASN1(ASN1Sequence.getInstance(p));
        } finally {
            if (aIn != null) try { aIn.close(); } catch (Exception ignore) {}
        }
    }

    public BigInteger getP() {
        return p;
    }

    public BigInteger getQ() {
        return q;
    }

    public BigInteger getG() {
        return g;
    }

    public BigInteger getY() {
        return y;
    }

    @Override
    public String getAlgorithm() {
        return keyAlgorithmName != null ? keyAlgorithmName : "UNKNOWN";
    }

    @Override
    public String getFormat() {
        return "X.509";
    }

    @Override
    public byte[] getEncoded() {
        return encoded != null ? encoded.clone() : null;
    }
}
