package util;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.PrivateKey;

public class PrivateKeyASN1 implements PrivateKey {

    private static final long serialVersionUID = 1L;

    private BigInteger p;       // 소수 p
    private BigInteger q;       // 소수 q
    private BigInteger g;       // 생성자 g
    private BigInteger y;       // 공개키 y = g^x mod p
    private BigInteger x;       // 개인키 x
    private BigInteger j;       // j 파라미터 (옵션)
    private byte[] seed;        // seed (옵션)
    private BigInteger counter; // counter (옵션)
    private byte[] encoded;     // PKCS#8 인코딩된 형식

    // 파싱한 키 알고리즘 (PrivateKeyInfo의 algorithm OID)
    private String keyAlgorithmOid;
    private String keyAlgorithmName;

    public PrivateKeyASN1(ASN1Sequence sequence) throws Exception {
        if (sequence == null) {
            throw new IllegalArgumentException("sequence is null");
        }
        if (sequence.size() < 3) {
            throw new IllegalArgumentException("Not a valid PKCS#8 PrivateKeyInfo (size < 3)");
        }

        // PKCS#8 전체 DER 저장
        this.encoded = sequence.getEncoded(ASN1Encoding.DER);

        // AlgorithmIdentifier 파싱
        ASN1Sequence algIdSeq = ASN1Sequence.getInstance(sequence.getObjectAt(1));
        parseAlgorithmParameters(algIdSeq);

        // privateKey(Octet String) 꺼내서 내부 ASN.1 다시 파싱
        ASN1OctetString keyOctets = ASN1OctetString.getInstance(sequence.getObjectAt(2));
        ASN1Primitive inner = ASN1Primitive.fromByteArray(keyOctets.getOctets());

        if (inner instanceof ASN1Sequence) {
            ASN1Sequence innerSeq = (ASN1Sequence) inner;
            parsePrivateKey(innerSeq);

        } else if (inner instanceof ASN1Integer) {
            ASN1Integer innerInt = (ASN1Integer) inner;
            this.x = innerInt.getValue();
            if (this.p != null && this.g != null) {
                this.y = this.g.modPow(this.x, this.p);
            }

        } else if (inner instanceof ASN1OctetString) {
            ASN1OctetString innerOs = (ASN1OctetString) inner;
            this.x = new BigInteger(1, innerOs.getOctets());

        } else {
            throw new IllegalArgumentException("Unsupported inner privateKey ASN.1 type: " + inner.getClass().getName());
        }
    }

    private void parseAlgorithmParameters(ASN1Sequence algId) throws Exception {
        AlgorithmIdentifier algorithmIdentifier = AlgorithmIdentifier.getInstance(algId);
        ASN1ObjectIdentifier oid = algorithmIdentifier.getAlgorithm();
        this.keyAlgorithmOid = oid.getId();

        // Java 8 switch on String은 OK
        if ("1.2.840.113549.1.1.1".equals(this.keyAlgorithmOid)) {
            this.keyAlgorithmName = "RSA";
        } else if ("1.2.840.10040.4.1".equals(this.keyAlgorithmOid)) {
            this.keyAlgorithmName = "DSA";
        } else if ("1.2.840.10045.2.1".equals(this.keyAlgorithmOid)) {
            this.keyAlgorithmName = "EC";
        } else {
            this.keyAlgorithmName = this.keyAlgorithmOid;
        }

        ASN1Encodable params = algorithmIdentifier.getParameters();
        if (params == null || params instanceof ASN1Null) {
            return;
        }

        // DSA parameters ::= SEQUENCE { p, q, g }
        if ("1.2.840.10040.4.1".equals(this.keyAlgorithmOid)) {
            ASN1Sequence dsaParams = ASN1Sequence.getInstance(params);
            if (dsaParams.size() >= 3) {
                this.p = ASN1Integer.getInstance(dsaParams.getObjectAt(0)).getValue();
                this.q = ASN1Integer.getInstance(dsaParams.getObjectAt(1)).getValue();
                this.g = ASN1Integer.getInstance(dsaParams.getObjectAt(2)).getValue();
            }
        }

        // EC curve OID 등은 필요하면 별도 필드로 저장하도록 확장 가능
    }

    private void parsePrivateKey(ASN1Sequence keySequence) {
        if (keySequence.size() >= 6) {
            BigInteger modulus    = ASN1Integer.getInstance(keySequence.getObjectAt(1)).getValue();
            BigInteger publicExp  = ASN1Integer.getInstance(keySequence.getObjectAt(2)).getValue();
            BigInteger privateExp = ASN1Integer.getInstance(keySequence.getObjectAt(3)).getValue();
            BigInteger prime1     = ASN1Integer.getInstance(keySequence.getObjectAt(4)).getValue();
            BigInteger prime2     = ASN1Integer.getInstance(keySequence.getObjectAt(5)).getValue();

            // 기존 필드명 유지한 매핑
            this.y = modulus;     // n
            this.g = publicExp;   // e
            this.x = privateExp;  // d
            this.p = prime1;      // p
            this.q = prime2;      // q
            return;
        }

        // 다른 케이스 최소 처리
        if (keySequence.size() == 1 && keySequence.getObjectAt(0) instanceof ASN1Integer) {
            this.x = ASN1Integer.getInstance(keySequence.getObjectAt(0)).getValue();
            if (this.p != null && this.g != null) {
                this.y = this.g.modPow(this.x, this.p);
            }
        }
    }

    public BigInteger getP() { return p; }
    public BigInteger getQ() { return q; }
    public BigInteger getG() { return g; }
    public BigInteger getY() { return y; }
    public BigInteger getX() { return x; }
    public BigInteger getJ() { return j; }

    @Override
    public String getAlgorithm() {
        return keyAlgorithmName != null ? keyAlgorithmName : "UNKNOWN";
    }

    @Override
    public String getFormat() {
        return "PKCS#8";
    }

    @Override
    public byte[] getEncoded() {
        return encoded != null ? encoded.clone() : null;
    }

    @Override
    public void destroy() {
        // 민감한 데이터 제거
        if (x != null) {
            x = BigInteger.ZERO;
        }
        if (encoded != null) {
            java.util.Arrays.fill(encoded, (byte) 0);
        }
    }

    @Override
    public boolean isDestroyed() {
        return x == null || x.equals(BigInteger.ZERO);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("Private Key ASN.1 Structure:\n");
        sb.append("  p: ").append(p != null ? p.toString(16) : "null").append("\n");
        sb.append("  q: ").append(q != null ? q.toString(16) : "null").append("\n");
        sb.append("  g: ").append(g != null ? g.toString(16) : "null").append("\n");
        sb.append("  y: ").append(y != null ? y.toString(16) : "null").append("\n");
        sb.append("  x: ").append(x != null ? x.toString(16) : "null").append("\n");
        if (j != null) {
            sb.append("  j: ").append(j.toString(16)).append("\n");
        }
        return sb.toString();
    }

    public static PrivateKeyASN1 fromPkcs8Der(byte[] pkcs8Der) throws Exception {
        try (ASN1InputStream aIn = new ASN1InputStream(new ByteArrayInputStream(pkcs8Der))) {
            ASN1Primitive p = aIn.readObject();
            return new PrivateKeyASN1(ASN1Sequence.getInstance(p));
        }
    }
}
