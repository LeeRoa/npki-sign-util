# 🔐 NPKI Sign Utility

[![Java](https://img.shields.io/badge/Java-17%2B-ED8B00?style=for-the-badge&logo=openjdk&logoColor=white)](https://openjdk.org/)
[![Gradle](https://img.shields.io/badge/Gradle-Build-02303A?style=for-the-badge&logo=gradle&logoColor=white)](https://gradle.org/)
[![Bouncy Castle](https://img.shields.io/badge/Security-Bouncy%20Castle-2E8B57?style=for-the-badge&logo=security&logoColor=white)](https://www.bouncycastle.org/)
[![License](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)](LICENSE)

> **NPKI (National Public Key Infrastructure)** 공인인증서 기반의 전자서명 및 키 관리 작업을 간편하게 처리하기 위한 Java 라이브러리입니다.  
> 복잡한 Bouncy Castle 구현체를 캡슐화하여, 몇 줄의 코드만으로 개인키 복호화 및 전자서명 생성 기능을 제공합니다.

---

## ✨ Features

이 라이브러리는 공인인증서(NPKI) 환경에서 필수적인 암호화 기능을 손쉽게 구현하도록 돕습니다.

- 🔑 **Private Key Decryption**: 암호화된 개인키 파일(`.key`)을 비밀번호로 복호화
- 📜 **Certificate Parsing**: X.509 인증서 파일(`.der`, `.cer`) 파싱 및 정보 추출
- ✍️ **Digital Signature**: 데이터 무결성 검증을 위한 전자서명(Signature) 생성
- 🛠 **Bouncy Castle Integration**: 검증된 보안 라이브러리(Bouncy Castle) 기반의 안전한 구현
- 📦 **Simple API**: 복잡한 암호화 로직을 추상화한 직관적인 메서드 제공

<br/>

