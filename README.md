# 🔐 NPKI Sign Utility

[![Java](https://img.shields.io/badge/Java-17%2B-ED8B00?style=for-the-badge&logo=openjdk&logoColor=white)](https://openjdk.org/)
[![Gradle](https://img.shields.io/badge/Gradle-Build-02303A?style=for-the-badge&logo=gradle&logoColor=white)](https://gradle.org/)
[![Bouncy Castle](https://img.shields.io/badge/Security-Bouncy%20Castle-2E8B57?style=for-the-badge&logo=security&logoColor=white)](https://www.bouncycastle.org/)
[![License](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)](LICENSE)

> **"복잡한 NPKI 전자서명, 파일 경로만 넣으세요."** > 공인인증서(NPKI) 기반의 서명 및 검증 로직을 단 한 줄의 코드로 처리할 수 있도록 캡슐화한 자바 라이브러리입니다. Bouncy Castle을 기반으로 구현되었습니다.

---

## ✨ Features

복잡한 과정(개인키 로드, 복호화, 서명 생성)을 메서드 하나로 통합했습니다.

- 🚀 **One-Liner Signing**: 인증서/개인키 파일 경로와 비밀번호만 있으면 즉시 서명 생성
- 🔑 **Auto Key Decryption**: 암호화된 개인키(`.key`) 복호화 로직 내장
- ✅ **Easy Verification**: 공개키 추출부터 검증까지 한 번에 처리
- 📦 **Standard Support**: `byte[]` 기반의 데이터 처리로 파일, 텍스트 등 모든 포맷 지원
- 🛡 **Bouncy Castle**: 검증된 보안 라이브러리를 사용한 안전한 구현

<br/>

## 🚀 Usage
SignUtil 클래스 하나로 서명 생성부터 검증까지 모두 처리할 수 있습니다.

1. 전자서명 생성 (Signing)
복잡하게 키 객체를 만들 필요 없습니다. 파일 경로와 비밀번호만 파라미터에 넘기면, 라이브러리가 알아서 개인키를 복호화하고 서명을 만들 수 있습니다.

```java
import util.SignUtil;
import java.util.Base64;

public class MyService {
    public void doSign() {
        try {
            // 1. 필요한 정보 준비 (파일 경로, 비밀번호, 원본 데이터)
            String certPath = "C:/data/SignCert.der";   // 공개키 인증서 경로
            String keyPath  = "C:/data/SignPri.key";    // 암호화된 개인키 경로
            char[] password = "my_password".toCharArray();
            byte[] message  = "중요한 데이터 원문".getBytes();

            // 2. 서명 생성 (이 한 줄로 끝!)
            // 내부적으로 개인키 복호화 -> 서명 생성 -> 자체 검증까지 수행합니다.
            byte[] signature = SignUtil.sign(certPath, keyPath, password, message);
            
            // 결과 확인
            System.out.println("Signature(Base64): " + Base64.getEncoder().encodeToString(signature));
            
        } catch (Exception e) {
            e.printStackTrace(); // 비밀번호 틀림, 파일 없음 등 예외 처리
        }
    }
}
```

2. 전자서명 검증 (Verification)
검증 역시 인증서 파일 경로만 있으면 공개키를 추출해서 바로 확인해 줍니다.

```java
import util.SignUtil;

public class MyService {
    public void doVerify(byte[] originalMessage, byte[] signature) {
        String certPath = "C:/data/SignCert.der";

        try {
            // 서명 검증 수행
            // 내부적으로 인증서 파싱 -> 공개키 추출 -> 검증 로직 수행
            SignUtil.verify(certPath, originalMessage, signature);
            
            // verify 메서드는 실패 시 내부에서 로그를 출력하거나 로직에 따라 false를 반환하도록 커스텀 가능
            System.out.println("검증 완료");
            
        } catch (Exception e) {
            System.out.println("서명 검증 실패 또는 오류 발생");
        }
    }
}
```

## 🛠 Tech Stack
- Language: Java 8

- Build Tool: Gradle 8.13

- Security Lib: Bouncy Castle (bcprov-jdk18on)
