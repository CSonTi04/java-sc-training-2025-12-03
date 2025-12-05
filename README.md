# Java Cryptography Architecture (JCA) Training

This repository contains comprehensive examples and demonstrations of Java's cryptographic capabilities using the Java Cryptography Architecture (JCA) and Bouncy Castle provider.

## 📚 Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Project Structure](#project-structure)
- [Topics Covered](#topics-covered)
  - [1. Security Providers](#1-security-providers)
  - [2. Random Number Generation](#2-random-number-generation)
  - [3. Encoding Schemes](#3-encoding-schemes)
  - [4. Hash Functions](#4-hash-functions)
  - [5. Message Authentication Codes (MAC)](#5-message-authentication-codes-mac)
  - [6. Symmetric Encryption](#6-symmetric-encryption)
  - [7. Asymmetric Encryption](#7-asymmetric-encryption)
  - [8. Digital Signatures](#8-digital-signatures)
  - [9. Certificates](#9-certificates)
  - [10. Certificate Chains](#10-certificate-chains)
  - [11. JAR Signing](#11-jar-signing)
  - [12. HTTPS/TLS Certificates](#12-httpstls-certificates)
- [OAuth 2.0 Authentication with Keycloak](#oauth-20-authentication-with-keycloak)
  - [OAuth 2.0 Authorization Code Grant Flow Diagram](#oauth-20-authorization-code-grant-flow-diagram)
  - [Flow Components](#flow-components)
  - [Detailed Flow Steps](#detailed-flow-steps)
  - [Security Features](#security-features-in-this-flow)
  - [Keycloak Benefits](#keycloak-benefits)
- [Employee Management Projects](#employee-management-projects)
  - [Architecture Overview](#architecture-overview)
  - [employees-backend](#employees-backend)
  - [employees-frontend](#employees-frontend)
  - [employees-standalone-form](#employees-standalone-form)
- [Running the Examples](#running-the-examples)
- [Additional Reading](#additional-reading)
- [Best Practices](#best-practices)

## Overview

This training project demonstrates various cryptographic operations in Java, covering fundamental concepts from basic encoding to advanced certificate chain validation. All examples use industry-standard algorithms and follow security best practices.

## Prerequisites

- **Java 21** (JDK 21.0.4 or later recommended)
- **Maven** 3.6+
- **Bouncy Castle** 1.82 (included as dependency)

## Project Structure

```
jca/
├── pom.xml
└── src/main/java/jca/
    ├── ProvidersMain.java           # Security providers enumeration
    ├── RandomMain.java              # Secure random number generation
    ├── HexMain.java                 # Hexadecimal encoding
    ├── Base64Main.java              # Base64 encoding
    ├── HashMain.java                # Cryptographic hashing
    ├── MacMain.java                 # Message Authentication Codes
    ├── KeysMain.java                # Symmetric key generation
    ├── CipherMain.java              # Symmetric encryption/decryption
    ├── KeyPairMain.java             # Asymmetric key pair generation
    ├── SignMain.java                # Digital signature creation
    ├── VerifySignMain.java          # Digital signature verification
    ├── CertificateMain.java         # X.509 certificate generation
    └── CertificateChainMain.java    # Certificate chain creation

signed-jar/
├── pom.xml
└── src/main/java/training/
    └── HelloWorld.java              # Simple class for JAR signing demo

hello-boot-https/
├── pom.xml
├── src/main/java/training/helloboothttps/
│   └── HelloBootHttpsApplication.java  # Spring Boot HTTPS demo
└── src/main/resources/
    └── application.properties       # HTTPS/TLS configuration

employees-backend/
├── pom.xml
├── src/main/java/employees/
│   ├── EmployeesApplication.java       # Spring Boot REST API backend
│   ├── EmployeesController.java        # REST endpoints (GET, POST, PUT, DELETE)
│   ├── EmployeesService.java           # Business logic layer
│   ├── EmployeesRepository.java        # Database persistence (JPA)
│   ├── Employee.java                   # Entity model
│   ├── EmployeeResource.java           # DTO for API responses
│   ├── EmployeeNotFoundException.java   # Custom exception
│   ├── EmployeesExceptionHandler.java  # Global exception handling
│   └── Violation.java                  # Validation error details
└── src/main/resources/
    └── db/changelog/                   # Liquibase database migrations

employees-frontend/
├── pom.xml
├── src/main/java/employees/
│   ├── EmployeesFrontendApplication.java  # Spring Boot Thymeleaf frontend
│   ├── EmployeesController.java           # Web UI controller
│   ├── EmployeesClient.java               # REST client for backend API
│   ├── EmployeesProperties.java           # Configuration properties
│   ├── ClientConfig.java                  # HTTP client configuration
│   └── Employee.java                      # DTO model
└── src/main/resources/
    ├── templates/                         # Thymeleaf HTML templates
    ├── static/                            # CSS, JavaScript, images
    └── application.properties             # Frontend configuration

employees-standalone-form/
├── pom.xml
├── src/main/java/employees/
│   ├── EmployeesApplication.java          # Spring Boot standalone form app
│   ├── EmployeesController.java           # Web UI controller with JPA
│   ├── EmployeesService.java              # Business logic layer
│   ├── EmployeesRepository.java           # Database persistence (JPA)
│   ├── Employee.java                      # Entity model
│   ├── EmployeeModel.java                 # Form model
│   └── EmployeeNotFoundException.java      # Custom exception
└── src/main/resources/
    ├── templates/                         # Thymeleaf HTML templates with forms
    ├── static/                            # CSS, JavaScript, images
    ├── db/changelog/                      # Liquibase database migrations
    └── application.properties             # Configuration properties
```

## Topics Covered

### 1. Security Providers

**File:** `ProvidersMain.java`

Demonstrates how to enumerate all available security providers and their supported algorithms.

**Key Concepts:**
- JCA Provider architecture
- Available cryptographic services
- Algorithm discovery

**Example Output:**
```
SUN
  Signature: SHA256withRSA
  MessageDigest: SHA-256
  ...
```

**Code Highlights:**
```java
for(var provider : Security.getProviders()) {
    System.out.println(provider.getName());
    for (var service : provider.getServices()) {
        System.out.println("  " + service.getType() + ": " + service.getAlgorithm());
    }
}
```

### 2. Random Number Generation

**File:** `RandomMain.java`

Shows proper use of cryptographically secure random number generators.

**Key Concepts:**
- Difference between `Random` and `SecureRandom`
- Platform-specific algorithms (e.g., `Windows-PRNG`)
- Strong random instances for high-security scenarios
- Entropy considerations and thread safety

**Security Notes:**
- ⚠️ Never use `java.util.Random` for cryptographic purposes
- ✅ Use `SecureRandom` for all security-sensitive random data
- ✅ Consider caching `SecureRandom.getInstanceStrong()` in ThreadLocal

**Example:**
```java
var random = SecureRandom.getInstanceStrong();
byte[] randomBytes = new byte[16]; // 128 bits
random.nextBytes(randomBytes);
```

### 3. Encoding Schemes

#### Hexadecimal Encoding
**File:** `HexMain.java`

Converts binary data to hexadecimal representation (base-16).

**Use Cases:**
- Human-readable binary data display
- Debugging cryptographic operations
- Key and hash visualization

**Example:**
```java
var hexFormat = HexFormat.of();
var hex = hexFormat.formatHex("Hello, World!".getBytes());
// Output: 48656c6c6f2c20576f726c6421
```

#### Base64 Encoding
**File:** `Base64Main.java`

Encodes binary data in Base64 format for text-safe transmission.

**Use Cases:**
- Email attachments
- Data URLs
- JSON/XML embedding
- Certificate encoding (PEM format)

**Features:**
- Handles special characters (newlines, tabs, etc.)
- Preserves binary data integrity
- URL-safe variants available

**Example:**
```java
String encoded = Base64.getEncoder().encodeToString(original.getBytes());
byte[] decoded = Base64.getDecoder().decode(encoded);
```

### 4. Hash Functions

**File:** `HashMain.java`

Demonstrates cryptographic hash functions (one-way functions).

**Key Concepts:**
- SHA-256 hash algorithm
- Fixed-size output (256 bits)
- Collision resistance
- Integrity verification

**Properties:**
- ✅ Deterministic (same input → same output)
- ✅ Fast to compute
- ✅ Avalanche effect (small input change → completely different hash)
- ✅ One-way (infeasible to reverse)
- ✅ Collision-resistant

**Example:**
```java
var digest = MessageDigest.getInstance("SHA-256");
var hash = digest.digest(input);
// Output: 32 bytes (256 bits)
```

**Common Algorithms:**
- SHA-256, SHA-384, SHA-512 (SHA-2 family) ✅
- SHA-1 (deprecated for security) ⚠️
- MD5 (broken, avoid) ❌

### 5. Message Authentication Codes (MAC)

**File:** `MacMain.java`

Demonstrates keyed-hash message authentication for integrity and authenticity.

**Key Concepts:**
- HMAC-SHA256 algorithm
- Symmetric key authentication
- Integrity + authenticity verification
- Timing-attack resistant comparison

**Difference from Hash:**
- Hash: Integrity only (anyone can verify)
- MAC: Integrity + Authenticity (requires secret key)

**Security Considerations:**
```java
// ❌ WRONG: Vulnerable to timing attacks
var isValid = Arrays.equals(signature, verifySignature);

// ✅ CORRECT: Constant-time comparison
var isValid = MessageDigest.isEqual(signature, verifySignature);
```

**Use Cases:**
- API authentication
- Cookie signing
- Message integrity in symmetric encryption

### 6. Symmetric Encryption

**Files:** `KeysMain.java`, `CipherMain.java`

Demonstrates AES encryption with GCM mode (Galois/Counter Mode).

**Key Concepts:**
- AES (Advanced Encryption Standard)
- GCM mode (provides encryption + authentication)
- Initialization Vector (IV) uniqueness
- Key sizes: 128, 192, 256 bits

**Architecture:**
```
Plaintext → AES-GCM → Ciphertext + Authentication Tag
                ↑
            Key + IV
```

**Example Flow:**
1. Generate AES-256 key
2. Generate random 12-byte IV
3. Encrypt with AES/GCM/NoPadding
4. Output: IV.Encrypted.Key (for demo purposes)
5. Decrypt using same key and IV

**Security Notes:**
- ✅ IV must be unique for each encryption
- ✅ GCM provides authenticated encryption (AEAD)
- ✅ Use `SecureRandom.getInstanceStrong()` for IV
- ⚠️ Never reuse IV with the same key

**Real-World Usage:**
```java
// Encryption
var cipher = Cipher.getInstance("AES/GCM/NoPadding");
var spec = new GCMParameterSpec(128, iv); // 128-bit auth tag
cipher.init(Cipher.ENCRYPT_MODE, key, spec);
var encrypted = cipher.doFinal(plaintext);

// Decryption
cipher.init(Cipher.DECRYPT_MODE, key, spec);
var decrypted = cipher.doFinal(encrypted);
```

### 7. Asymmetric Encryption

**File:** `KeyPairMain.java`

Demonstrates RSA key pair generation and properties.

**Key Concepts:**
- Public/Private key pairs
- RSA algorithm (2048-bit recommended minimum)
- Key components (modulus, exponents)
- Key formats (PKCS#8 for private, X.509 for public)

**RSA Properties:**
```
Public Key:  (n, e) - can be freely distributed
Private Key: (n, d) - must be kept secret
```

**Use Cases:**
- Digital signatures
- Key exchange
- Certificate-based authentication

**Key Sizes:**
- 1024 bits: ❌ Deprecated
- 2048 bits: ✅ Standard (sufficient for most uses)
- 3072 bits: ✅ High security
- 4096 bits: ✅ Maximum security (slower)

### 8. Digital Signatures

**Files:** `SignMain.java`, `VerifySignMain.java`

Demonstrates RSA digital signatures with SHA-256.

**Key Concepts:**
- SHA256withRSA algorithm
- Private key for signing
- Public key (from certificate) for verification
- Keystore management (PKCS#12)

**Signature Flow:**
```
Message → Hash (SHA-256) → Sign with Private Key → Signature
                                                        ↓
Message → Hash (SHA-256) ← Verify with Public Key ← Signature
```

**Implementation:**

**Signing:**
```java
var signature = Signature.getInstance("SHA256withRSA");
signature.initSign(privateKey);
signature.update(data);
var signBytes = signature.sign();
```

**Verification:**
```java
var signature = Signature.getInstance("SHA256withRSA");
signature.initVerify(certificate.getPublicKey());
signature.update(data);
var valid = signature.verify(signatureBytes);
```

**Use Cases:**
- Code signing
- Document authentication
- Software updates
- TLS/SSL handshakes

### 9. Certificates

**File:** `CertificateMain.java`

Demonstrates X.509 certificate creation and management using Bouncy Castle.

**Key Concepts:**
- X.509 certificate structure
- Self-signed certificates
- Certificate formats (DER, PEM)
- Keystore formats (PKCS#12)
- Private key encryption (PKCS#8)

**Certificate Components:**
- Subject: Certificate owner (CN, O, C)
- Issuer: Certificate signer
- Public Key: Owner's public key
- Serial Number: Unique identifier
- Validity Period: Not before/after dates
- Signature: Issuer's signature

**File Formats:**

| Format | Type | Extension | Description |
|--------|------|-----------|-------------|
| DER | Binary | .der, .cer | Binary encoding of X.509 |
| PEM | Text | .pem | Base64-encoded DER with headers |
| PKCS#12 | Binary | .p12, .pfx | Container for cert + private key |
| PKCS#8 | Binary/Text | .key | Private key format |

**Example Output Files:**
- `training-certificate.der` - Binary certificate
- `training-certificate.pem` - Text certificate
- `training-certificate-private.der` - Unencrypted private key
- `training-certificate-private.pem` - Encrypted private key (password: `changeit`)
- `training-keystore.p12` - Certificate + private key bundle
- `training-keystore-just-certificate.p12` - Certificate only

**Keystore Operations:**
```java
// Create keystore with private key + certificate
var keyStore = KeyStore.getInstance("PKCS12");
keyStore.load(null, null);
keyStore.setKeyEntry("training-key", privateKey, 
    "changeit".toCharArray(), new X509Certificate[]{cert});

// Create keystore with certificate only
keyStore.setCertificateEntry("training-certificate", cert);
```

### 10. Certificate Chains

**File:** `CertificateChainMain.java`

Demonstrates creation of a complete PKI (Public Key Infrastructure) certificate chain.

**Chain Structure:**
```
Root CA (self-signed)
    ↓ signs
Intermediate CA
    ↓ signs
End-Entity Certificate (www.example.com)
```

**Key Concepts:**
- Trust anchors (Root CA)
- Certificate authorities (CA)
- Path validation
- Basic Constraints extension
- Key Usage extensions
- Path length constraints

**Extensions Explained:**

**Basic Constraints:**
- CA flag: Indicates if certificate can sign other certificates
- Path length: Maximum number of intermediate CAs allowed below this one

**Key Usage:**
- `keyCertSign`: Can sign certificates
- `cRLSign`: Can sign Certificate Revocation Lists
- `digitalSignature`: Can create digital signatures
- `keyEncipherment`: Can encrypt keys

**Extended Key Usage:**
- `serverAuth`: TLS/SSL server authentication
- `clientAuth`: TLS/SSL client authentication
- `codeSigning`: Code signing
- `emailProtection`: Email signing/encryption

**Path Length Constraints:**
```
Root CA (pathLen=1) → Can sign 1 level of intermediate CAs
    ↓
Intermediate CA (pathLen=0) → Can sign end-entity certs only
    ↓
Server Certificate → Cannot sign anything
```

**Output:**
- `chain.p7b` - PKCS#7 file containing the complete certificate chain

**Validation:**
```
Client validates: Server Cert → Intermediate CA → Root CA (trusted)
```

### 11. JAR Signing

**Directory:** `signed-jar/`

Demonstrates how to digitally sign Java Archive (JAR) files for code authentication and integrity.

**Key Concepts:**
- Code signing for Java applications
- JAR file integrity protection
- Publisher verification
- Security policy enforcement

#### What is JAR Signing?

JAR signing is the process of digitally signing a Java Archive file to:
1. **Verify authenticity** - Proves who created/published the code
2. **Ensure integrity** - Detects any tampering or modification
3. **Enable trust** - Allows users to trust and run the application
4. **Grant permissions** - Required for certain security-sensitive operations

#### How JAR Signing Works

```
JAR File → Hash each entry → Sign hashes with private key → Add signature to JAR
                                                                    ↓
                                                      MANIFEST.MF (file hashes)
                                                      *.SF (signature file)
                                                      *.RSA/DSA (signature block)
```

**Inside a Signed JAR:**
```
META-INF/
  ├── MANIFEST.MF       - Contains SHA-256 hash of each file
  ├── MYKEY.SF          - Signature file (hash of manifest entries)
  └── MYKEY.RSA         - Signature block (encrypted with private key)
```

**Verification Process:**
1. Extract public key from certificate in `.RSA` file
2. Verify signature in `.SF` file matches manifest
3. Verify each file's hash matches the manifest entry
4. Check certificate validity and trust chain

#### Why Do We Need JAR Signing?

**Security Benefits:**
- ✅ **Prevents tampering** - Any modification invalidates the signature
- ✅ **Verifies publisher** - Confirms the code source
- ✅ **Enables applets** - Required for Java applets with special permissions
- ✅ **Code trust** - Users can verify the developer's identity
- ✅ **Policy enforcement** - Java security policies can require signed code

**Real-World Use Cases:**
- Distributing commercial Java applications
- Java Web Start applications (now deprecated, but concept lives on)
- Browser applets (deprecated, but historically important)
- Enterprise software deployment
- Plugin systems requiring trusted code
- Mobile applications (Android APK signing uses similar concepts)

#### Step-by-Step JAR Signing Process

**1. Generate a Key Pair and Certificate**

```cmd
keytool -genkeypair -dname "cn=Trainer, ou=Training, c=HU" ^
    -alias mykey ^
    -keyalg RSA ^
    -keysize 2048 ^
    -storetype PKCS12 ^
    -keystore mykeystore.p12 ^
    -storepass storepass ^
    -validity 180
```

**Parameters Explained:**
- `-genkeypair` - Generate a public/private key pair
- `-dname` - Distinguished name (CN=Common Name, OU=Organizational Unit, C=Country)
- `-alias mykey` - Alias to reference this key in the keystore
- `-keyalg RSA` - Use RSA algorithm
- `-keysize 2048` - 2048-bit key (minimum recommended)
- `-storetype PKCS12` - Modern keystore format (recommended over JKS)
- `-keystore mykeystore.p12` - Output keystore file
- `-storepass storepass` - Keystore password (⚠️ use strong password in production!)
- `-validity 180` - Certificate valid for 180 days

**2. Verify Keystore Contents**

```cmd
keytool -list -keystore mykeystore.p12 -storepass storepass -v
```

**Output Example:**
```
Keystore type: PKCS12
Keystore provider: SUN

Your keystore contains 1 entry

Alias name: mykey
Creation date: Dec 3, 2025
Entry type: PrivateKeyEntry
Certificate chain length: 1
Certificate[1]:
Owner: CN=Trainer, OU=Training, C=HU
Issuer: CN=Trainer, OU=Training, C=HU (self-signed)
Serial number: 5f3e8a9b
Valid from: Tue Dec 03 10:00:00 CET 2025 until: Mon Jun 01 10:00:00 CEST 2026
```

**3. Build the JAR File**

```cmd
cd C:\Repos\java-sc-training-2025-12-03\signed-jar
mvn clean package
```

This creates: `target/signed-jar-1.0-SNAPSHOT.jar`

**4. Sign the JAR**

```cmd
jarsigner -storetype PKCS12 ^
    -keystore mykeystore.p12 ^
    -storepass storepass ^
    -signedjar target\signed-jar-1.0-signed-SNAPSHOT.jar ^
    target\signed-jar-1.0-SNAPSHOT.jar ^
    mykey
```

**Parameters:**
- `-storetype PKCS12` - Keystore type
- `-keystore mykeystore.p12` - Path to keystore
- `-storepass storepass` - Keystore password
- `-signedjar <output>` - Name for signed JAR (optional, modifies in-place if omitted)
- `<input.jar>` - Original JAR file
- `mykey` - Alias of the key to use for signing

**Output:**
```
jar signed.

Warning:
The signer's certificate is self-signed.
```

⚠️ **Note:** Self-signed certificates trigger warnings. Production code should use certificates from trusted CAs.

**5. Verify the Signature**

```cmd
jarsigner -verify -verbose -certs target\signed-jar-1.0-signed-SNAPSHOT.jar
```

**Command Options:**
- `-verify` - Verify the signed JAR
- `-verbose` - Show detailed information about each entry
- `-certs` - Display certificate details

**Successful Output:**
```
         156 Tue Dec 03 10:15:32 CET 2025 META-INF/MANIFEST.MF
         234 Tue Dec 03 10:15:32 CET 2025 META-INF/MYKEY.SF
        1234 Tue Dec 03 10:15:32 CET 2025 META-INF/MYKEY.RSA
sm       456 Tue Dec 03 10:10:00 CET 2025 training/HelloWorld.class

  s = signature was verified
  m = entry is listed in manifest
  k = at least one certificate was found in keystore

jar verified.

Warning:
This jar contains entries whose signer certificate is self-signed.
```

**Status Flags Explained:**
- `s` - Signature was verified successfully
- `m` - Entry is listed in the manifest
- `k` - At least one certificate was found in the keystore
- `i` - Entry is ignored (not in manifest, added after signing)
- `x` - Signature is invalid or cannot be verified

**Simple Verification (No Verbose):**
```cmd
jarsigner -verify target\signed-jar-1.0-signed-SNAPSHOT.jar
```

Successful output:
```
jar verified.
```

Failed output:
```
jarsigner: java.lang.SecurityException: Invalid signature file digest for Manifest main attributes
```

#### Demonstrating Verification Failure

To understand what happens when a JAR is tampered with, you can create a script that modifies a signed JAR and shows the verification failure.

**Create `test-jar-tampering.bat`:**
```batch
@echo off
echo ========================================
echo JAR Signature Tampering Demonstration
echo ========================================
echo.

REM Step 1: Build and sign the JAR
echo [1] Building JAR...
cd signed-jar
call mvn -q clean package
if errorlevel 1 (
    echo Build failed!
    exit /b 1
)

echo [2] Signing JAR...
jarsigner -storetype PKCS12 ^
    -keystore ..\mykeystore.p12 ^
    -storepass storepass ^
    -signedjar target\signed-jar-signed.jar ^
    target\signed-jar-1.0-SNAPSHOT.jar ^
    mykey 2>nul
echo     Signed: target\signed-jar-signed.jar
echo.

REM Step 2: Verify original signature
echo [3] Verifying ORIGINAL signed JAR...
jarsigner -verify target\signed-jar-signed.jar
if errorlevel 1 (
    echo     FAILED: Original JAR verification failed!
) else (
    echo     SUCCESS: Original JAR verified correctly
)
echo.

REM Step 3: Create tampered copy
echo [4] Creating TAMPERED copy...
copy target\signed-jar-signed.jar target\signed-jar-tampered.jar >nul

REM Extract JAR
mkdir temp-extract 2>nul
cd temp-extract
jar -xf ..\target\signed-jar-tampered.jar

REM Modify a class file (add a space/byte to change it)
echo. >> training\HelloWorld.class

REM Repackage JAR
jar -cf ..\target\signed-jar-tampered.jar *
cd ..
rmdir /s /q temp-extract
echo     Created: target\signed-jar-tampered.jar (modified HelloWorld.class)
echo.

REM Step 4: Verify tampered signature
echo [5] Verifying TAMPERED JAR...
echo     Expected: VERIFICATION FAILURE
echo.
jarsigner -verify -verbose target\signed-jar-tampered.jar
if errorlevel 1 (
    echo.
    echo     EXPECTED FAILURE: Tampered JAR verification failed!
    echo     This proves the signature detected the modification.
) else (
    echo.
    echo     UNEXPECTED: Tampered JAR still verified (this should not happen)
)
echo.

echo ========================================
echo Demonstration Complete
echo ========================================
echo.
echo Summary:
echo   - Original JAR: Signature valid
echo   - Tampered JAR: Signature invalid
echo.
echo This proves that any modification to a signed JAR
echo will be detected during verification.
echo ========================================

cd ..
```

**Run the script:**
```cmd
test-jar-tampering.bat
```

**Expected Output:**
```
========================================
JAR Signature Tampering Demonstration
========================================

[1] Building JAR...
[2] Signing JAR...
    Signed: target\signed-jar-signed.jar

[3] Verifying ORIGINAL signed JAR...
jar verified.
    SUCCESS: Original JAR verified correctly

[4] Creating TAMPERED copy...
    Created: target\signed-jar-tampered.jar (modified HelloWorld.class)

[5] Verifying TAMPERED JAR...
    Expected: VERIFICATION FAILURE

jarsigner: java.lang.SecurityException: SHA-256 digest error for training/HelloWorld.class

    EXPECTED FAILURE: Tampered JAR verification failed!
    This proves the signature detected the modification.

========================================
Demonstration Complete
========================================

Summary:
  - Original JAR: Signature valid
  - Tampered JAR: Signature invalid

This proves that any modification to a signed JAR
will be detected during verification.
========================================
```

#### Alternative Tampering Scenarios

**Scenario 1: Modify a single byte in a class file**
```batch
REM After extracting the JAR
echo X >> training\HelloWorld.class
```

**Scenario 2: Add a new file (unsigned entry)**
```batch
REM After extracting the JAR
echo Malicious code > training\Malware.class
jar -cf ..\target\signed-jar-tampered.jar *
```

When verified, unsigned entries show without the `s` flag:
```
sm       456 Tue Dec 03 10:10:00 CET 2025 training/HelloWorld.class
         123 Tue Dec 03 11:00:00 CET 2025 training/Malware.class

Warning: This jar contains unsigned entries which have not been integrity-checked.
```

**Scenario 3: Remove META-INF signature files**
```batch
REM After extracting
del META-INF\MYKEY.SF
del META-INF\MYKEY.RSA
jar -cf ..\target\signed-jar-tampered.jar *
```

Verification fails completely:
```
jarsigner: unable to verify jar; no manifest found
```

**Scenario 4: Modify MANIFEST.MF directly**
```batch
REM After extracting
echo Tampered: true >> META-INF\MANIFEST.MF
jar -cf ..\target\signed-jar-tampered.jar *
```

Verification fails:
```
jarsigner: java.lang.SecurityException: Invalid signature file digest for Manifest main attributes
```

**6. Inspect JAR Contents**

```cmd
jar -tf target\signed-jar-1.0-signed-SNAPSHOT.jar
```

**Output:**
```
META-INF/
META-INF/MANIFEST.MF
training/
training/HelloWorld.class
META-INF/MYKEY.SF
META-INF/MYKEY.RSA
```

#### Understanding the Signature Files

**MANIFEST.MF** - Contains SHA-256 digests of all files:
```
Manifest-Version: 1.0
Created-By: 21.0.4 (Oracle Corporation)

Name: training/HelloWorld.class
SHA-256-Digest: 3Bf7xK9... (base64 encoded hash)
```

**MYKEY.SF** - Signature File (hashes of manifest entries):
```
Signature-Version: 1.0
SHA-256-Digest-Manifest: 5Kj8mN2... (hash of entire manifest)
Created-By: 21.0.4 (Oracle Corporation)

Name: training/HelloWorld.class
SHA-256-Digest: 7Lp4qR1... (hash of manifest entry for this file)
```

**MYKEY.RSA** - Signature Block (binary file containing):
- Signer's certificate (public key)
- Encrypted hash of the .SF file (using private key)
- Certificate chain (if applicable)

#### Complete Example with signed-jar Module

**Project Structure:**
```
signed-jar/
├── pom.xml
└── src/main/java/training/
    └── HelloWorld.java
```

**HelloWorld.java:**
```java
package training;

public class HelloWorld {
    public static void main(String[] args) {
        System.out.println("Hello from signed JAR!");
    }
}
```

**Full Workflow:**
```cmd
REM 1. Create keystore
keytool -genkeypair -dname "cn=Trainer, ou=Training, c=HU" ^
    -alias mykey -keyalg RSA -keysize 2048 -storetype PKCS12 ^
    -keystore mykeystore.p12 -storepass storepass -validity 180

REM 2. Build JAR
cd signed-jar
mvn clean package

REM 3. Sign JAR
jarsigner -storetype PKCS12 -keystore mykeystore.p12 ^
    -storepass storepass ^
    -signedjar target\signed-jar-1.0-signed-SNAPSHOT.jar ^
    target\signed-jar-1.0-SNAPSHOT.jar mykey

REM 4. Verify signature
jarsigner -verify -verbose -certs target\signed-jar-1.0-signed-SNAPSHOT.jar

REM 5. Run signed JAR
java -jar target\signed-jar-1.0-signed-SNAPSHOT.jar
```

#### Timestamp Server (Recommended)

Adding a timestamp ensures the signature remains valid even after the certificate expires:

```cmd
jarsigner -storetype PKCS12 ^
    -keystore mykeystore.p12 ^
    -storepass storepass ^
    -tsa http://timestamp.digicert.com ^
    -signedjar target\signed-jar-1.0-signed-SNAPSHOT.jar ^
    target\signed-jar-1.0-SNAPSHOT.jar ^
    mykey
```

**Why Timestamp?**
- Without timestamp: Signature becomes invalid when certificate expires
- With timestamp: Signature proves "code was signed while cert was valid"

**Trusted Timestamp Services:**
- `http://timestamp.digicert.com`
- `http://timestamp.globalsign.com/tsa/r6advanced1`
- `http://tsa.starfieldtech.com`
- `http://timestamp.comodoca.com/rfc3161`

#### Production Best Practices

**Certificate Management:**
- ✅ Use certificates from trusted Certificate Authorities (CA)
- ✅ Use organization-validated (OV) or extended-validated (EV) certificates
- ✅ Set appropriate validity periods (1-3 years typical)
- ✅ Renew certificates before expiration
- ✅ Use separate certificates for different products

**Key Protection:**
- ✅ Use strong keystore passwords (16+ characters)
- ✅ Store keystores in secure, access-controlled locations
- ✅ Use Hardware Security Modules (HSM) for high-value keys
- ✅ Implement key rotation policies
- ✅ Backup keystores securely
- ❌ Never commit keystores to version control
- ❌ Never share private keys

**Signing Process:**
- ✅ Always use timestamp servers
- ✅ Verify signatures after signing
- ✅ Keep audit logs of signing operations
- ✅ Use build automation for consistent signing
- ✅ Sign all JARs in a multi-JAR application

**Distribution:**
- ✅ Provide public certificate for users to verify
- ✅ Document signature verification steps
- ✅ Use HTTPS for JAR distribution
- ✅ Provide checksums (SHA-256) alongside JARs

#### Security Considerations

**What JAR Signing Does NOT Do:**
- ❌ Does not encrypt the code (code is still readable)
- ❌ Does not prevent reverse engineering
- ❌ Does not guarantee the code is safe/malware-free
- ❌ Does not protect runtime memory or data

**What JAR Signing DOES:**
- ✅ Proves the publisher's identity
- ✅ Detects any tampering after signing
- ✅ Enables Java security policies
- ✅ Provides non-repudiation

**Potential Issues:**
- Self-signed certificates → Users see warnings
- Expired certificates → Signatures become invalid (without timestamp)
- Revoked certificates → Signatures no longer trusted
- Weak algorithms (SHA-1, RSA-1024) → Security vulnerabilities

#### Maven Plugin Alternative

You can automate JAR signing in your build process:

**pom.xml:**
```xml
<build>
    <plugins>
        <plugin>
            <groupId>org.apache.maven.plugins</groupId>
            <artifactId>maven-jarsigner-plugin</artifactId>
            <version>3.0.0</version>
            <executions>
                <execution>
                    <id>sign</id>
                    <goals>
                        <goal>sign</goal>
                    </goals>
                </execution>
                <execution>
                    <id>verify</id>
                    <goals>
                        <goal>verify</goal>
                    </goals>
                </execution>
            </executions>
            <configuration>
                <keystore>mykeystore.p12</keystore>
                <alias>mykey</alias>
                <storepass>storepass</storepass>
                <tsa>http://timestamp.digicert.com</tsa>
            </configuration>
        </plugin>
    </plugins>
</build>
```

Then simply run:
```cmd
mvn clean package
```

The JAR will be automatically signed during the build.

#### Additional Reading - JAR Signing

**Official Documentation:**
- [Oracle JAR Signing Guide](https://docs.oracle.com/javase/tutorial/deployment/jar/signing.html)
- [jarsigner Tool Reference](https://docs.oracle.com/en/java/javase/21/docs/specs/man/jarsigner.html)
- [keytool Documentation](https://docs.oracle.com/en/java/javase/21/docs/specs/man/keytool.html)
- [JAR File Specification](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/jar.html)

**Standards:**
- [RFC 2315 - PKCS #7: Cryptographic Message Syntax](https://tools.ietf.org/html/rfc2315)
- [RFC 5652 - Cryptographic Message Syntax (CMS)](https://tools.ietf.org/html/rfc5652)
- [RFC 3161 - Time-Stamp Protocol (TSP)](https://tools.ietf.org/html/rfc3161)

**Code Signing Best Practices:**
- [Oracle Code Signing for Java Developers](https://www.oracle.com/java/technologies/javase/seccodeguide.html)
- [NIST Guidelines on Software Integrity](https://csrc.nist.gov/publications/detail/sp/800-218/final)
- [Microsoft Trusted Root Program Requirements](https://docs.microsoft.com/en-us/security/trusted-root/program-requirements)
- [DigiCert Code Signing Best Practices](https://www.digicert.com/kb/code-signing/code-signing-best-practices.htm)

**Related Topics:**
- [Android APK Signing](https://developer.android.com/studio/publish/app-signing) - Similar concept for Android apps
- [Windows Authenticode](https://docs.microsoft.com/en-us/windows-hardware/drivers/install/authenticode) - Code signing for Windows
- [Apple Code Signing](https://developer.apple.com/support/code-signing/) - macOS/iOS code signing
- [Sigstore](https://www.sigstore.dev/) - New standard for signing, verification, and provenance

**Tools:**
- [Maven JAR Signer Plugin](https://maven.apache.org/plugins/maven-jarsigner-plugin/)
- [Gradle Signing Plugin](https://docs.gradle.org/current/userguide/signing_plugin.html)
- [KeyStore Explorer](https://keystore-explorer.org/) - GUI for managing keystores
- [Portecle](http://portecle.sourceforge.net/) - User-friendly keystore tool

**Security Research:**
- [JAR Hell and ClassLoader Issues](https://blog.oio.de/2014/01/31/java-jar-hell/)
- [Common JAR Signing Mistakes](https://tersesystems.com/blog/2018/09/08/jar-signing/)
- [Certificate Pinning](https://owasp.org/www-community/controls/Certificate_and_Public_Key_Pinning)

### 12. HTTPS/TLS Certificates

**Directory:** `hello-boot-https/`

Demonstrates how to configure HTTPS/TLS in a Spring Boot application using self-signed certificates and how to manage certificate replacement without server restart.

**Key Concepts:**
- TLS/SSL certificate generation for web servers
- HTTPS configuration in Spring Boot
- Self-signed vs CA-signed certificates
- Certificate trust management
- Hot-reloading certificates without restart

#### What is HTTPS/TLS?

HTTPS (HTTP Secure) uses TLS (Transport Layer Security) to encrypt communication between a client (browser) and server. This provides:

- **Encryption**: Data is encrypted in transit, preventing eavesdropping
- **Authentication**: Server identity is verified through certificates
- **Integrity**: Data cannot be modified without detection

**How TLS Works:**
```
Client → [Hello] → Server
Client ← [Certificate + Server Hello] ← Server
Client → [Verify Certificate]
Client → [Encrypted Key Exchange] → Server
Client ↔ [Encrypted Communication] ↔ Server
```

#### Why Do We Need HTTPS Certificates?

**Security Benefits:**
- ✅ **Prevents Man-in-the-Middle attacks** - Encrypted communication
- ✅ **Verifies server identity** - Client knows who they're talking to
- ✅ **Data integrity** - Detects tampering
- ✅ **Trust** - Browsers show security indicators (padlock icon)
- ✅ **SEO ranking** - Google favors HTTPS sites
- ✅ **Compliance** - Required by PCI-DSS, GDPR, and other regulations

**What Happens Without HTTPS?**
- ❌ Passwords transmitted in plaintext
- ❌ Session cookies can be stolen
- ❌ Data can be intercepted and read
- ❌ Browser warnings ("Not Secure")
- ❌ Some browser features disabled (geolocation, camera, etc.)

#### Certificate Types

**1. Self-Signed Certificates**
- Created and signed by the same entity (no trusted CA)
- **Pros:** Free, instant, full control
- **Cons:** Browser warnings, no trust chain, manual trust required
- **Use Cases:** Development, testing, internal applications

**2. CA-Signed Certificates**
- Signed by a trusted Certificate Authority
- **Pros:** Browser trusted, no warnings, professional appearance
- **Cons:** Costs money (or effort for free CAs), validation required
- **Use Cases:** Production websites, public-facing applications

#### Generating Self-Signed Certificates for HTTPS

**Method 1: Interactive (with prompts)**

```cmd
keytool -genkeypair -alias demo -keyalg RSA -keysize 2048 ^
    -storetype PKCS12 -keystore demo.p12 -validity 3650
```

**You will be prompted for:**
```
Enter keystore password: [enter password]
Re-enter new password: [enter password]
What is your first and last name?
  [Unknown]:  localhost
What is the name of your organizational unit?
  [Unknown]:  Development
What is the name of your organization?
  [Unknown]:  Training
What is the name of your City or Locality?
  [Unknown]:  Budapest
What is the name of your State or Province?
  [Unknown]:  Budapest
What is the two-letter country code for this unit?
  [Unknown]:  HU
Is CN=localhost, OU=Development, O=Training, L=Budapest, ST=Budapest, C=HU correct?
  [no]:  yes
```

**Parameters Explained:**
- `-genkeypair` - Generate a public/private key pair with certificate
- `-alias demo` - Alias to identify this certificate in the keystore
- `-keyalg RSA` - Use RSA algorithm
- `-keysize 2048` - 2048-bit RSA key (minimum recommended for HTTPS)
- `-storetype PKCS12` - Modern keystore format (recommended over JKS)
- `-keystore demo.p12` - Output keystore file name
- `-validity 3650` - Certificate valid for 3650 days (~10 years)

**Method 2: Non-Interactive (automated/scripted)**

```cmd
keytool -genkeypair -alias demo2 -keyalg RSA -keysize 2048 ^
    -storetype PKCS12 -keystore demo2.p12 -validity 3650 ^
    -dname "CN=localhost, OU=Development, O=Training, L=Budapest, ST=Budapest, C=HU" ^
    -storepass storepass
```

**Additional Parameters:**
- `-dname "CN=..."` - Distinguished Name (non-interactive)
  - **CN** (Common Name): Hostname of your server (e.g., `localhost`, `www.example.com`)
  - **OU** (Organizational Unit): Department (e.g., `Development`, `IT`)
  - **O** (Organization): Company name
  - **L** (Locality): City
  - **ST** (State): State/Province
  - **C** (Country): Two-letter country code
- `-storepass storepass` - Keystore password (non-interactive)

⚠️ **Important:** The **CN (Common Name)** must match the hostname used to access the server:
- For local development: `CN=localhost`
- For production: `CN=www.example.com` or `CN=*.example.com` (wildcard)

**Method 3: With SAN (Subject Alternative Names) for multiple domains**

```cmd
keytool -genkeypair -alias demo3 -keyalg RSA -keysize 2048 ^
    -storetype PKCS12 -keystore demo3.p12 -validity 3650 ^
    -dname "CN=localhost, OU=Development, O=Training, C=HU" ^
    -storepass storepass ^
    -ext "SAN=dns:localhost,dns:127.0.0.1,dns:demo.local,ip:127.0.0.1"
```

This allows the certificate to be valid for multiple hostnames/IPs.

**Method 4: Using mkcert (Recommended for Local Development)**

[mkcert](https://mkcert.org/) is a simple tool for making locally-trusted development certificates. It automatically creates and installs a local CA in your system trust store, so browsers trust your development certificates without warnings.

**Why mkcert?**
- ✅ **Zero configuration** - Works immediately, no browser warnings
- ✅ **Automatic trust** - Installs local CA in system trust store
- ✅ **Multi-platform** - Works on Windows, macOS, Linux
- ✅ **Simple workflow** - One command to generate trusted certificates
- ✅ **Development focused** - Perfect for localhost and local domains
- ⚠️ **Local only** - Not for production use (by design)

**Installation on Windows (via winget):**

```cmd
winget install mkcert
```

**Alternative Installation Methods:**

```cmd
# Via Chocolatey
choco install mkcert

# Via Scoop
scoop bucket add extras
scoop install mkcert

# Manual download
# Download from https://github.com/FiloSottile/mkcert/releases
```

**Setup and Usage:**

**1. Install local CA (one-time setup)**

```cmd
mkcert -install
```

This creates a local Certificate Authority and adds it to your system trust store. Now all certificates generated by mkcert will be trusted by your browsers and system.

**Output:**
```
Created a new local CA at "C:\Users\YourName\AppData\Local\mkcert"
The local CA is now installed in the system trust store! ⚡️
```

**2. Generate certificate for localhost**

```cmd
mkcert localhost 127.0.0.1 ::1
```

This creates two files:
- `localhost+2.pem` - Certificate (public key)
- `localhost+2-key.pem` - Private key

**3. Convert to PKCS12 for Java/Spring Boot**

```cmd
# Create PKCS12 keystore from PEM files
openssl pkcs12 -export -out localhost.p12 ^
    -inkey localhost+2-key.pem ^
    -in localhost+2.pem ^
    -name localhost ^
    -passout pass:changeit
```

If OpenSSL is not installed:
```cmd
# Install OpenSSL via winget
winget install OpenSSL.Light
```

**4. Use in Spring Boot application.properties**

```properties
server.port=8443
server.ssl.enabled=true
server.ssl.key-store=classpath:localhost.p12
server.ssl.key-store-password=changeit
server.ssl.key-store-type=PKCS12
server.ssl.key-alias=localhost
```

**5. Access without browser warnings! 🎉**

```
https://localhost:8443
```

No more "Your connection is not private" warnings - the certificate is fully trusted!

**Advanced mkcert Usage:**

```cmd
# Generate certificate for custom domains
mkcert myapp.local "*.myapp.local" myapp.test

# Generate certificate with specific output names
mkcert -cert-file myapp.crt -key-file myapp.key myapp.local

# Show CA location
mkcert -CAROOT

# Uninstall local CA (when done with development)
mkcert -uninstall
```

**mkcert vs keytool:**

| Feature              | mkcert               | keytool                   |
|----------------------|----------------------|---------------------------|
| **Trust**            | Automatic (local CA) | Manual (browser warnings) |
| **Setup**            | One command install  | Multi-step configuration  |
| **Browser warnings** | None ✅               | Yes ⚠️                    |
| **Production use**   | No (local only)      | Yes                       |
| **Cross-platform**   | Yes                  | Yes                       |
| **Best for**         | Local development    | Production/testing        |

**Important Security Notes:**

⚠️ **mkcert is for development only!**
- The local CA private key is stored on your machine
- Anyone with access to the CA key can create trusted certificates
- Never use mkcert certificates in production
- Never share your mkcert CA root key

**Real-World Development Workflow:**

```cmd
# One-time setup (per machine)
winget install mkcert
mkcert -install

# Per project
cd hello-boot-https
mkcert localhost 127.0.0.1
openssl pkcs12 -export -out localhost.p12 ^
    -inkey localhost+2-key.pem ^
    -in localhost+2.pem ^
    -name localhost ^
    -passout pass:changeit

# Move to resources
move localhost.p12 src\main\resources\

# Update application.properties
# server.ssl.key-store=classpath:localhost.p12
# server.ssl.key-store-password=changeit

# Run - no browser warnings!
mvn spring-boot:run
```

**Benefits for Development Teams:**

- ✅ New developers get started faster (no certificate trust setup)
- ✅ Consistent HTTPS experience across team
- ✅ Test HTTPS-only features (Service Workers, WebCrypto, etc.)
- ✅ Realistic development environment matching production
- ✅ No security warnings cluttering development

**Learn More:**

- Official website: [https://mkcert.org/](https://mkcert.org/)
- GitHub repository: [https://github.com/FiloSottile/mkcert](https://github.com/FiloSottile/mkcert)
- How it works: [https://github.com/FiloSottile/mkcert#how-it-works](https://github.com/FiloSottile/mkcert#how-it-works)

#### Configuring Spring Boot for HTTPS

**1. Generate Certificate**

```cmd
cd hello-boot-https
keytool -genkeypair -alias demo -keyalg RSA -keysize 2048 ^
    -storetype PKCS12 -keystore demo.p12 -validity 3650 ^
    -dname "CN=localhost, OU=Training, O=Training, C=HU" ^
    -storepass changeit
```

**2. Configure application.properties**

```properties
# HTTPS Configuration
server.port=8443
server.ssl.enabled=true
server.ssl.key-store=classpath:demo.p12
server.ssl.key-store-password=changeit
server.ssl.key-store-type=PKCS12
server.ssl.key-alias=demo

# Optional: Require HTTPS
# server.ssl.enabled=true
```

**3. Run Spring Boot Application**

```cmd
cd hello-boot-https
mvn spring-boot:run
```

**4. Access via Browser**

```
https://localhost:8443
```

You'll see a browser warning because it's self-signed. Click "Advanced" → "Proceed to localhost".

#### What If HTTPS Certificate Is Not Signed?

When using a self-signed certificate, browsers will show security warnings:

**Chrome/Edge:**
```
Your connection is not private
NET::ERR_CERT_AUTHORITY_INVALID
```

**Firefox:**
```
Warning: Potential Security Risk Ahead
```

**Why?** Browsers don't trust self-signed certificates because there's no trusted CA vouching for the certificate's authenticity.

**Solutions:**

**Option 1: Accept the Warning (Development Only)**
- Click "Advanced" → "Proceed to localhost (unsafe)"
- ⚠️ **Never do this for unknown websites!**
- ✅ Acceptable for `localhost` during development

**Option 2: Add Certificate to Windows Trusted Root Store**

This makes Windows (and all browsers) trust your self-signed certificate.

```cmd
# Export certificate from keystore
keytool -exportcert -alias demo -keystore demo.p12 ^
    -storepass changeit -file demo.cer

# Import to Windows Trusted Root Certification Authorities
certutil -addstore -user Root demo.cer
```

**Verify in Windows:**
1. Win + R → `certmgr.msc`
2. Trusted Root Certification Authorities → Certificates
3. Find your certificate (CN=localhost)

**Remove certificate when done:**
```cmd
certutil -delstore -user Root demo
```

**Option 3: Use Let's Encrypt (Free CA-Signed Certificates)**

[Let's Encrypt](https://letsencrypt.org/) provides free, automated, trusted SSL/TLS certificates.

**Requirements:**
- Domain name (cannot use `localhost`)
- Publicly accessible server (port 80 or 443)
- ACME client (e.g., Certbot)

**Basic Process:**
```bash
# Install Certbot
sudo apt-get install certbot

# Obtain certificate (standalone mode)
sudo certbot certonly --standalone -d example.com

# Certificates saved to:
# /etc/letsencrypt/live/example.com/fullchain.pem
# /etc/letsencrypt/live/example.com/privkey.pem

# Convert to PKCS12 for Java
openssl pkcs12 -export -in fullchain.pem -inkey privkey.pem \
    -out keystore.p12 -name demo -passout pass:changeit
```

**Auto-Renewal (Let's Encrypt certs expire every 90 days):**
```bash
sudo certbot renew
```

**Spring Boot Configuration:**
```properties
server.ssl.key-store=/etc/letsencrypt/live/example.com/keystore.p12
server.ssl.key-store-password=changeit
```

**Alternatives to Let's Encrypt:**
- [ZeroSSL](https://zerossl.com/) - Free certificates like Let's Encrypt
- [Cloudflare](https://www.cloudflare.com/) - Free SSL with CDN
- Commercial CAs: DigiCert, GlobalSign, Sectigo (paid, extended validation)

#### Certificate Replacement Without Restart

One of the powerful features demonstrated is **hot-swapping certificates without restarting the server**.

**Why Is This Important?**

- **Zero Downtime**: No service interruption during certificate renewal
- **Automated Renewal**: Can integrate with Let's Encrypt auto-renewal
- **Security Updates**: Quickly respond to compromised certificates
- **Testing**: Switch between test and production certificates

**How It Works:**

The `demo2.p12` keystore demonstrates that Spring Boot can be configured to reload SSL context dynamically.

**Step-by-Step Hot-Swap:**

**1. Server is running with `demo.p12`**

```properties
server.ssl.key-store=classpath:demo.p12
```

**2. Generate new certificate (`demo2.p12`)**

```cmd
keytool -genkeypair -alias demo2 -keyalg RSA -keysize 2048 ^
    -storetype PKCS12 -keystore demo2.p12 -validity 3650 ^
    -dname "CN=localhost, OU=Training2, O=Training, C=HU" ^
    -storepass storepass
```

**3. Update configuration (Spring Cloud Config or hot-reload)**

```properties
server.ssl.key-store=classpath:demo2.p12
server.ssl.key-store-password=storepass
server.ssl.key-alias=demo2
```

**4. Reload SSL context programmatically**

**Approach A: Spring Actuator Refresh**
```java
@RestController
public class CertificateRefreshController {
    
    @Autowired
    private WebServerApplicationContext webServerContext;
    
    @PostMapping("/admin/refresh-ssl")
    public String refreshSsl() {
        // Trigger SSL context reload
        // Implementation depends on embedded server (Tomcat/Jetty/Undertow)
        return "SSL certificate reloaded";
    }
}
```

**Approach B: Using Spring Cloud Config**
```properties
# application.properties
spring.cloud.config.enabled=true
management.endpoints.web.exposure.include=refresh

# After changing certificate
POST http://localhost:8443/actuator/refresh
```

**Approach C: File Watching (Production-Grade)**
```java
@Configuration
public class SslReloadConfiguration {
    
    @Value("${server.ssl.key-store}")
    private String keystorePath;
    
    @PostConstruct
    public void watchKeystore() throws IOException {
        WatchService watchService = FileSystems.getDefault().newWatchService();
        Path path = Paths.get(keystorePath).getParent();
        path.register(watchService, StandardWatchEventKinds.ENTRY_MODIFY);
        
        new Thread(() -> {
            while (true) {
                WatchKey key = watchService.take();
                // Reload SSL context when keystore file changes
                reloadSslContext();
                key.reset();
            }
        }).start();
    }
    
    private void reloadSslContext() {
        // Reload implementation
    }
}
```

**5. Verify new certificate**

```cmd
# Check which certificate is being used
openssl s_client -connect localhost:8443 -showcerts

# Output will show the new certificate details
# Verify: OU=Training2 (from demo2.p12)
```

**Benefits of Certificate Hot-Reload:**

✅ **No Downtime**: Server keeps serving requests during cert update
✅ **Automated Renewal**: Integrate with Let's Encrypt auto-renewal scripts
✅ **Blue-Green Deployments**: Test new certificates before full rollout
✅ **Quick Response**: Fast mitigation of compromised certificates
✅ **Maintenance Windows**: No need to schedule downtime for cert renewal

**Real-World Scenario:**

```bash
# Cron job runs daily
0 0 * * * certbot renew --post-hook "curl -X POST http://localhost:8080/admin/refresh-ssl"
```

When Let's Encrypt auto-renews your certificate (every 60 days), the post-hook triggers SSL reload without restart.

#### Verifying HTTPS Certificates

**Using Browser Developer Tools:**

1. Open https://localhost:8443
2. Click the padlock icon → "Certificate"
3. Verify:
   - Issued to: CN=localhost
   - Issued by: CN=localhost (self-signed)
   - Valid from/to dates
   - Public key: RSA 2048 bits

**Using OpenSSL:**

```cmd
# View certificate details
openssl s_client -connect localhost:8443 -showcerts

# Check specific details
openssl s_client -connect localhost:8443 | openssl x509 -noout -text

# Verify certificate dates
openssl s_client -connect localhost:8443 | openssl x509 -noout -dates

# Check certificate chain
openssl s_client -connect localhost:8443 -showcerts | openssl storeutl -noout -text -certs /dev/stdin
```

**Using Keytool:**

```cmd
# List keystore contents
keytool -list -v -keystore demo.p12 -storepass changeit

# Check certificate validity
keytool -list -keystore demo.p12 -storepass changeit
```

**Using curl:**

```cmd
# Accept self-signed (insecure, testing only)
curl -k https://localhost:8443

# Verify with specific CA certificate
curl --cacert demo.cer https://localhost:8443

# Show certificate details
curl -v https://localhost:8443
```

#### Production Best Practices

**Certificate Management:**
- ✅ Use certificates from trusted CAs (Let's Encrypt, DigiCert, etc.)
- ✅ Use 2048-bit RSA minimum (4096-bit for high security)
- ✅ Consider ECC certificates (256-bit) for better performance
- ✅ Set appropriate validity periods (Let's Encrypt: 90 days, commercial: 1-2 years)
- ✅ Implement automated renewal (critical for Let's Encrypt)
- ✅ Monitor certificate expiration dates
- ✅ Use Subject Alternative Names (SAN) for multiple domains

**TLS Configuration:**
- ✅ Use TLS 1.2 minimum (TLS 1.3 recommended)
- ✅ Disable weak cipher suites
- ✅ Enable Perfect Forward Secrecy (PFS)
- ✅ Implement HSTS (HTTP Strict Transport Security)
- ✅ Use strong Diffie-Hellman parameters

**Spring Boot Production Configuration:**

```properties
# HTTPS Configuration
server.port=8443
server.ssl.enabled=true
server.ssl.key-store=file:/etc/ssl/certs/keystore.p12
server.ssl.key-store-password=${SSL_KEYSTORE_PASSWORD}
server.ssl.key-store-type=PKCS12
server.ssl.key-alias=production

# TLS Protocol
server.ssl.protocol=TLS
server.ssl.enabled-protocols=TLSv1.2,TLSv1.3

# Cipher Suites (strong ciphers only)
server.ssl.ciphers=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256

# Client Certificate Authentication (optional)
server.ssl.client-auth=need
server.ssl.trust-store=file:/etc/ssl/certs/truststore.p12
server.ssl.trust-store-password=${SSL_TRUSTSTORE_PASSWORD}

# Redirect HTTP to HTTPS
server.http.port=8080
```

**Redirect HTTP to HTTPS (Spring Boot):**

```java
@Configuration
public class HttpsRedirectConfiguration {
    
    @Bean
    public ServletWebServerFactory servletContainer() {
        TomcatServletWebServerFactory tomcat = new TomcatServletWebServerFactory() {
            @Override
            protected void postProcessContext(Context context) {
                SecurityConstraint securityConstraint = new SecurityConstraint();
                securityConstraint.setUserConstraint("CONFIDENTIAL");
                SecurityCollection collection = new SecurityCollection();
                collection.addPattern("/*");
                securityConstraint.addCollection(collection);
                context.addConstraint(securityConstraint);
            }
        };
        tomcat.addAdditionalTomcatConnectors(redirectConnector());
        return tomcat;
    }
    
    private Connector redirectConnector() {
        Connector connector = new Connector("org.apache.coyote.http11.Http11NioProtocol");
        connector.setScheme("http");
        connector.setPort(8080);
        connector.setSecure(false);
        connector.setRedirectPort(8443);
        return connector;
    }
}
```

**Environment Variables (Security):**
```cmd
# Windows
set SSL_KEYSTORE_PASSWORD=your-secure-password

# Linux/Mac
export SSL_KEYSTORE_PASSWORD=your-secure-password
```

**Docker Deployment:**
```dockerfile
# Dockerfile
FROM openjdk:21-jdk-slim
COPY target/app.jar /app.jar
COPY certs/keystore.p12 /etc/ssl/certs/keystore.p12
ENTRYPOINT ["java", "-jar", "/app.jar"]

# docker-compose.yml
services:
  app:
    build: .
    ports:
      - "8443:8443"
    environment:
      - SSL_KEYSTORE_PASSWORD=${SSL_KEYSTORE_PASSWORD}
    volumes:
      - ./certs:/etc/ssl/certs:ro
```

**Testing HTTPS Configuration:**

```bash
# Test with SSL Labs (for public sites)
https://www.ssllabs.com/ssltest/

# Test with testssl.sh
./testssl.sh https://localhost:8443

# Test with nmap
nmap --script ssl-enum-ciphers -p 8443 localhost
```

#### Common Issues and Solutions

**Issue 1: Certificate hostname mismatch**
```
Error: Certificate for <localhost> doesn't match any of the subject alternative names
```
**Solution:** Ensure CN matches the hostname, or use SAN extension:
```cmd
keytool -genkeypair ... -ext "SAN=dns:localhost,ip:127.0.0.1"
```

**Issue 2: Certificate expired**
```
Error: certificate has expired
```
**Solution:** Generate new certificate with longer validity or implement auto-renewal

**Issue 3: Keystore password incorrect**
```
Error: Keystore was tampered with, or password was incorrect
```
**Solution:** Verify password in application.properties matches keytool password

**Issue 4: Port already in use**
```
Error: Address already in use: bind
```
**Solution:** Change port or kill process using port 8443:
```cmd
netstat -ano | findstr :8443
taskkill /PID <PID> /F
```

**Issue 5: Browser still shows old certificate after hot-swap**
```
Browser cache showing old certificate
```
**Solution:** 
- Clear browser SSL cache
- Use incognito/private mode
- Restart browser
- Check server actually reloaded certificate

#### Additional Reading - HTTPS/TLS

**Official Documentation:**
- [Spring Boot SSL Configuration](https://docs.spring.io/spring-boot/docs/current/reference/html/application-properties.html#application-properties.server.server.ssl)
- [Oracle JSSE Reference Guide](https://docs.oracle.com/en/java/javase/21/security/java-secure-socket-extension-jsse-reference-guide.html)
- [keytool Documentation](https://docs.oracle.com/en/java/javase/21/docs/specs/man/keytool.html)

**Standards:**
- [RFC 8446 - TLS 1.3](https://tools.ietf.org/html/rfc8446)
- [RFC 5246 - TLS 1.2](https://tools.ietf.org/html/rfc5246)
- [RFC 6125 - Domain Name Validation](https://tools.ietf.org/html/rfc6125)
- [RFC 6797 - HTTP Strict Transport Security (HSTS)](https://tools.ietf.org/html/rfc6797)

**Tools and Services:**
- [Let's Encrypt](https://letsencrypt.org/) - Free SSL/TLS certificates
- [Certbot](https://certbot.eff.org/) - Automatic certificate management
- [mkcert](https://mkcert.org/) - **Recommended for local development** - Zero-config local CA, creates trusted certificates instantly (`winget install mkcert`)
- [SSL Labs Server Test](https://www.ssllabs.com/ssltest/) - Test your HTTPS configuration
- [testssl.sh](https://testssl.sh/) - Command-line TLS/SSL testing

**Best Practices:**
- [Mozilla SSL Configuration Generator](https://ssl-config.mozilla.org/)
- [OWASP Transport Layer Protection](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)
- [Qualys SSL/TLS Deployment Best Practices](https://github.com/ssllabs/research/wiki/SSL-and-TLS-Deployment-Best-Practices)

- [Qualys SSL/TLS Deployment Best Practices](https://github.com/ssllabs/research/wiki/SSL-and-TLS-Deployment-Best-Practices)

**Certificate Authorities:**
- [Let's Encrypt](https://letsencrypt.org/) - Free, automated
- [ZeroSSL](https://zerossl.com/) - Free alternative
- [DigiCert](https://www.digicert.com/) - Commercial, EV certificates
- [GlobalSign](https://www.globalsign.com/) - Commercial
- [Sectigo (formerly Comodo)](https://sectigo.com/) - Commercial

## OAuth 2.0 Authentication with Keycloak

This section explains the OAuth 2.0 Authorization Code Grant flow with Keycloak, a comprehensive identity and access management solution.

### What is Keycloak?

Keycloak is an open-source Identity and Access Management (IAM) solution developed by Red Hat. It provides enterprise-grade security features for modern applications and services with minimal coding required.

**Key Features:**
- 🔐 **Single Sign-On (SSO)** - Users authenticate once and access multiple applications
- 🌐 **Social Login** - Integration with Google, Facebook, GitHub, LinkedIn, etc.
- 👥 **User Federation** - Connect to existing LDAP or Active Directory
- 🛡️ **Standard Protocols** - OpenID Connect, OAuth 2.0, SAML 2.0
- 🔑 **Multi-Factor Authentication** - OTP, WebAuthn, SMS
- 📊 **Admin Console** - Web-based UI for managing users, roles, and clients
- 🎨 **Customizable Themes** - Branded login pages and emails
- 🔌 **Extensible** - Custom authentication flows, event listeners, providers

### Keycloak Setup and Configuration

#### Installation Methods

**1. Standalone Server (Development):**
```bash
# Download Keycloak
wget https://github.com/keycloak/keycloak/releases/download/23.0.0/keycloak-23.0.0.zip
unzip keycloak-23.0.0.zip
cd keycloak-23.0.0

# Start in development mode
bin/kc.sh start-dev

# Access admin console at http://localhost:8080
# Default credentials: admin/admin
```

**2. Docker (Quick Start):**
```bash
docker run -p 8080:8080 \
  -e KEYCLOAK_ADMIN=admin \
  -e KEYCLOAK_ADMIN_PASSWORD=admin \
  quay.io/keycloak/keycloak:23.0.0 \
  start-dev
```

**3. Docker Compose (Recommended for Development):**
```yaml
version: '3.8'
services:
  keycloak:
    image: quay.io/keycloak/keycloak:23.0.0
    environment:
      KEYCLOAK_ADMIN: admin
      KEYCLOAK_ADMIN_PASSWORD: admin
      KC_DB: postgres
      KC_DB_URL: jdbc:postgresql://postgres:5432/keycloak
      KC_DB_USERNAME: keycloak
      KC_DB_PASSWORD: keycloak
    command: start-dev
    ports:
      - "8080:8080"
    depends_on:
      - postgres
  
  postgres:
    image: postgres:15
    environment:
      POSTGRES_DB: keycloak
      POSTGRES_USER: keycloak
      POSTGRES_PASSWORD: keycloak
    volumes:
      - postgres_data:/var/lib/postgresql/data

volumes:
  postgres_data:
```

#### Keycloak Configuration Steps

**Step 1: Create a Realm**

A realm is a space where you manage users, applications, roles, and groups. Think of it as a tenant in a multi-tenant system.

```
Admin Console → Master (dropdown) → Create Realm
- Name: training-realm
- Enabled: ON
```

**Step 2: Create a Client**

A client represents your application that will use Keycloak for authentication.

```
Realm Settings → Clients → Create Client
- Client ID: employees-app
- Client Protocol: openid-connect
- Client Authentication: ON (for confidential clients)
- Valid Redirect URIs: http://localhost:8081/*, http://localhost:8081/login/oauth2/code/keycloak
- Web Origins: http://localhost:8081
- Backchannel Logout URL: http://localhost:8081/logout
```

**Client Settings:**
- **Access Type**: confidential (server-side apps) or public (SPAs, mobile)
- **Standard Flow Enabled**: ON (Authorization Code Flow)
- **Direct Access Grants Enabled**: OFF (disable Resource Owner Password Credentials)
- **Service Accounts Enabled**: ON (for client credentials flow)
- **Authorization Enabled**: ON (for fine-grained permissions)

**Step 3: Create Roles**

Roles define what users can do in your application.

```
Realm Settings → Roles → Create Role
- Role Name: USER
- Description: Standard user role

Create another role:
- Role Name: ADMIN
- Description: Administrator role
```

**Step 4: Create Users**

```
Users → Add User
- Username: john.doe
- Email: john.doe@example.com
- First Name: John
- Last Name: Doe
- Email Verified: ON
- Enabled: ON

Set Password:
Users → john.doe → Credentials → Set Password
- Password: password123
- Temporary: OFF

Assign Roles:
Users → john.doe → Role Mappings
- Assign Role: USER
```

**Step 5: Client Scopes and Mappers**

Client scopes define what information is included in tokens.

```
Client Scopes → Create Client Scope
- Name: employee-access
- Protocol: openid-connect
- Include in Token Scope: ON

Add Mapper (to include custom claims):
- Mapper Type: User Attribute
- Name: department
- User Attribute: department
- Token Claim Name: department
- Claim JSON Type: String
```

**Step 6: Configure Spring Boot Application**

Add dependencies in `pom.xml`:
```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-oauth2-client</artifactId>
</dependency>
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-oauth2-resource-server</artifactId>
</dependency>
```

Configure `application.yaml`:
```yaml
spring:
  security:
    oauth2:
      client:
        registration:
          keycloak:
            client-id: employees-app
            client-secret: ${KEYCLOAK_CLIENT_SECRET}
            scope: openid, profile, email, roles
            authorization-grant-type: authorization_code
            redirect-uri: "{baseUrl}/login/oauth2/code/{registrationId}"
        provider:
          keycloak:
            issuer-uri: http://localhost:8080/realms/training-realm
            user-name-attribute: preferred_username
      resourceserver:
        jwt:
          issuer-uri: http://localhost:8080/realms/training-realm
          jwk-set-uri: http://localhost:8080/realms/training-realm/protocol/openid-connect/certs
```

### Keycloak Realm Export/Import

**Export Realm Configuration:**
```bash
# Export realm to file
bin/kc.sh export --dir /tmp/keycloak-export --realm training-realm

# Export includes:
# - Clients
# - Roles
# - Users (without passwords by default)
# - Client scopes
# - Authentication flows
```

**Import Realm:**
```bash
# Import realm from file
bin/kc.sh import --file /tmp/keycloak-export/training-realm.json
```

**Realm JSON Example:**
```json
{
  "realm": "training-realm",
  "enabled": true,
  "sslRequired": "external",
  "registrationAllowed": false,
  "loginWithEmailAllowed": true,
  "duplicateEmailsAllowed": false,
  "resetPasswordAllowed": true,
  "editUsernameAllowed": false,
  "bruteForceProtected": true,
  "clients": [
    {
      "clientId": "employees-app",
      "enabled": true,
      "publicClient": false,
      "redirectUris": ["http://localhost:8081/*"],
      "webOrigins": ["http://localhost:8081"]
    }
  ],
  "roles": {
    "realm": [
      {"name": "USER"},
      {"name": "ADMIN"}
    ]
  }
}
```

### OAuth 2.0 Authorization Code Grant Flow Diagram

The following diagram illustrates the complete OAuth 2.0 Authorization Code Grant flow (PKCE - Proof Key for Code Exchange):

![OAuth 2.0 Authorization Code Grant Flow with Keycloak](./images/keycloack.png)

### Flow Components

**Three Main Actors:**

1. **Felhasználó, böngészővel** (User with Browser)
   - The end user initiating the login process
   - Interacts with the client application through a web browser

2. **Client Frontend alkalmazás** (Client Frontend Application)
   - The web application the user is accessing
   - Initiates OAuth flow and handles redirects
   - Stores tokens (access_token, refresh_token, id_token) in Session/Cache

3. **Authorization Server - Keycloak** (Keycloak)
   - Central identity provider
   - Authenticates users
   - Issues security tokens (access token, refresh token, id token)
   - Provides public key for token verification

4. **Resource Server Backend alkalmazás** (Resource Server Backend Application)
   - Protected API that requires valid tokens
   - Validates access tokens
   - Returns user resources if token is valid
   - Uses Keycloak's public key to verify token signatures

### Detailed Flow Steps

#### Step 1: Application Registration and Initial Request (Alkalmazás felkeresése)
- User accesses the client frontend application
- Application initiates OAuth 2.0 flow with PKCE support
- **Request parameters:**
  - `response_type=code` - Request authorization code
  - `client_id` - Application identifier
  - `scope` - Requested permissions
  - `state` - CSRF protection token
  - `redirect_uri` - Where to return after authentication
  - `nonce` - Token validation parameter
  - `code_challenge` - PKCE: Derived from code verifier
  - `code_challenge_method` - PKCE: Usually "S256" (SHA256)

#### Step 2: User Authentication and Consent (Bejelentkezési kérés, bejelentkezés, consent)
- User is redirected to Keycloak login page
- User authenticates with credentials (username/password, MFA, etc.)
- User grants permission to the application
- **Keycloak returns:**
  - `state` - Original state parameter (CSRF protection)
  - `session_state` - Keycloak session identifier
  - `iss` (issuer) - Authorization server identity
  - `code` - Authorization code (short-lived, ~10 minutes)

#### Step 3: Authorization Code Exchange (Oldal lekérése)
- Frontend application receives the authorization code
- Validates state parameter matches original request
- Sends authorization code back to backend
- **Authorization header parameters:**
  - `grant_type=authorization_code` - Token grant type
  - `redirect_uri` - Must match initial request
  - `code` - Authorization code from step 2
  - `code_verifier` - PKCE: Original random value
  - Client credentials (via Basic Auth or client secret)

#### Step 4: Token Request (Token lekérése)
- Backend sends code and code_verifier to Keycloak token endpoint
- Keycloak verifies:
  - Authorization code validity
  - Code hasn't been used before
  - code_verifier matches original code_challenge
  - Client credentials are valid
  - Redirect URI matches
- **Keycloak returns tokens:**
  - `access_token` - JWT token for API access (short-lived, ~5 minutes)
  - `refresh_token` - Token to obtain new access tokens (long-lived, ~30 days)
  - `id_token` - JWT containing user information (OpenID Connect)
  - `token_type` - "Bearer"
  - `expires_in` - Access token expiration time

#### Step 5: Token Storage (Token tárolása)
- Tokens are securely stored:
  - In **Session** (Server-side): Secure, HttpOnly cookie
  - In **Cache** (Server-side): In-memory store
  - NOT in browser localStorage (XSS vulnerability)
- Server maintains:
  - `access_token` - For API requests
  - `refresh_token` - For obtaining new tokens
  - `id_token` - User identity information

#### Step 6: Resource Request (Erőforrás lekérése)
- Client sends API request to Resource Server Backend
- Includes `access_token` in Authorization header:
  ```
  Authorization: Bearer eyJhbGciOiJSUzI1NiIs...
  ```
- Backend receives request and validates token

#### Step 7: Public Key Retrieval and Token Validation (Publikus kulcs lekérése)
- Resource Server Backend requests `publikus kulcs` (public key) from Keycloak
- Keycloak provides RSA public key for signature verification
- Backend validates token by:
  1. Verifying JWT signature using public key
  2. Checking token expiration (`exp` claim)
  3. Verifying issuer (`iss` claim) matches Keycloak URL
  4. Checking required claims and scopes
- If valid: Grant access to protected resource
- If invalid: Return 401 Unauthorized

### Security Features in This Flow

**PKCE (Proof Key for Code Exchange):**
- Protects against authorization code interception attacks
- `code_challenge` prevents attackers from exchanging captured codes
- Mandatory for public clients (SPAs, mobile apps)
- `code_verifier` proves code ownership

**State Parameter:**
- Prevents CSRF (Cross-Site Request Forgery) attacks
- Frontend generates random state
- Must match state returned in callback
- Validated before processing authorization code

**Short-Lived Access Tokens:**
- Access tokens expire quickly (typically 5-15 minutes)
- Limits damage if token is compromised
- Requires refresh token for new access tokens

**Refresh Token Rotation:**
- New refresh token issued with each access token refresh
- Old refresh token automatically invalidated
- Reduces attack surface

**Token Encryption and Signing:**
- Tokens are JWTs: digitally signed (not encrypted)
- Signature verifies token hasn't been tampered with
- Public key allows any service to verify tokens
- Keycloak is only service that can create/sign tokens

### Keycloak Benefits

✅ **Centralized Authentication** - Single source of truth for user identity
✅ **Multiple Authentication Methods** - Username/password, social login, MFA, LDAP
✅ **Token Management** - Automatic token expiration and refresh
✅ **User Management** - User creation, roles, permissions
✅ **Fine-Grained Authorization** - Scopes, roles, attributes
✅ **Audit Logging** - Track all authentication events
✅ **High Availability** - Cluster support, load balancing
✅ **Multi-Tenancy** - Support for multiple realms (isolated domains)
✅ **Protocol Support** - OpenID Connect, OAuth 2.0, SAML 2.0
✅ **Custom Extensions** - Theme customization, event listeners

### Related Projects in Repository

The following projects in this repository demonstrate OAuth 2.0 with Keycloak:

- **employees-backend-oauth2** - REST API protected with OAuth 2.0 tokens (Resource Server)
- **employees-frontend-oauth2** - Frontend application with OAuth 2.0 integration (OAuth2 Client)
- **employees-standalone-form-spring-security** - Monolithic app with Spring Security form-based authentication

**Detailed documentation for these projects is available in the [Employee Management Projects](#employee-management-projects) section below.**

### Common Use Cases

**1. Web Application Authorization**
```
User → Web App (Frontend) → Keycloak (Login) → Web App → REST API
```

**2. Mobile App Authorization**
```
User → Mobile App → Keycloak (Login) → Mobile App → REST API
```

**3. Multiple Services with Single Sign-On (SSO)**
```
User → Service A → Keycloak (Login) → Service A
User → Service B → Uses existing Keycloak session → Service B (no re-auth)
```

**4. Microservices Authorization**
```
API Gateway → Validates Token → Routes to Microservice
Microservice → Can trust token (signed by Keycloak) → Process request
```

### Best Practices

✅ **Always use HTTPS** - Protect tokens in transit
✅ **Use PKCE** - Even for confidential clients
✅ **Store tokens securely** - Server-side session, HttpOnly cookies
✅ **Validate tokens completely** - Signature, expiration, issuer, scope
✅ **Implement token refresh** - Refresh before expiration
✅ **Short token lifetime** - 5-15 minutes for access tokens
✅ **Longer refresh token lifetime** - 24 hours to 30 days
✅ **Implement logout** - Invalidate tokens on logout
✅ **Monitor for anomalies** - Track unusual authentication patterns
✅ **Use strong client secrets** - Random, long strings (if needed)

❌ **Never store tokens in localStorage** - Vulnerable to XSS attacks
❌ **Never log tokens** - Could expose sensitive information
❌ **Don't trust client-side claims** - Always validate on server
❌ **Don't skip token validation** - Signature verification is critical
❌ **Don't use unencrypted HTTP** - Tokens transmitted in plaintext

### Additional Resources

- [Keycloak Official Documentation](https://www.keycloak.org/documentation)
- [OAuth 2.0 Specification (RFC 6749)](https://tools.ietf.org/html/rfc6749)
- [PKCE Specification (RFC 7636)](https://tools.ietf.org/html/rfc7636)
- [OpenID Connect Specification](https://openid.net/specs/openid-connect-core-1_0.html)
- [Spring Security OAuth2 Guide](https://spring.io/guides/tutorials/spring-boot-oauth2/)
- [Keycloak Spring Boot Adapter](https://www.keycloak.org/docs/latest/securing_apps/#_spring_boot_adapter)
- [Baeldung Keycloak Guide](https://www.baeldung.com/spring-boot-keycloak)

### Spring Security Integration Examples

#### Example 1: Resource Server Configuration (Backend API)

**SecurityConfig.java:**
```java
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(authz -> authz
                .requestMatchers("/api/public/**").permitAll()
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                .requestMatchers("/api/employees/**").hasAnyRole("USER", "ADMIN")
                .anyRequest().authenticated()
            )
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt
                    .jwtAuthenticationConverter(jwtAuthenticationConverter())
                )
            )
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )
            .csrf(csrf -> csrf.disable()); // Stateless API
        
        return http.build();
    }

    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter grantedAuthoritiesConverter = 
            new JwtGrantedAuthoritiesConverter();
        
        // Convert Keycloak realm_access.roles to Spring Security authorities
        grantedAuthoritiesConverter.setAuthoritiesClaimName("realm_access.roles");
        grantedAuthoritiesConverter.setAuthorityPrefix("ROLE_");

        JwtAuthenticationConverter jwtAuthenticationConverter = 
            new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(
            grantedAuthoritiesConverter);
        
        return jwtAuthenticationConverter;
    }
}
```

**Controller with Method Security:**
```java
@RestController
@RequestMapping("/api/employees")
public class EmployeeController {

    @Autowired
    private EmployeeService employeeService;

    @GetMapping
    @PreAuthorize("hasAnyRole('USER', 'ADMIN')")
    public ResponseEntity<List<EmployeeDto>> getAllEmployees() {
        return ResponseEntity.ok(employeeService.findAll());
    }

    @PostMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<EmployeeDto> createEmployee(
            @Valid @RequestBody CreateEmployeeRequest request,
            @AuthenticationPrincipal Jwt jwt) {
        
        // Access token claims
        String username = jwt.getClaimAsString("preferred_username");
        String email = jwt.getClaimAsString("email");
        
        EmployeeDto employee = employeeService.create(request, username);
        return ResponseEntity.status(HttpStatus.CREATED).body(employee);
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN') or @employeeService.isOwner(#id, authentication.name)")
    public ResponseEntity<EmployeeDto> updateEmployee(
            @PathVariable Long id,
            @Valid @RequestBody UpdateEmployeeRequest request) {
        
        EmployeeDto updated = employeeService.update(id, request);
        return ResponseEntity.ok(updated);
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Void> deleteEmployee(@PathVariable Long id) {
        employeeService.delete(id);
        return ResponseEntity.noContent().build();
    }
}
```

#### Example 2: OAuth2 Client Configuration (Frontend Application)

**SecurityConfig.java:**
```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(authz -> authz
                .requestMatchers("/", "/public/**", "/css/**", "/js/**").permitAll()
                .requestMatchers("/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()
            )
            .oauth2Login(oauth2 -> oauth2
                .loginPage("/oauth2/authorization/keycloak")
                .defaultSuccessUrl("/employees", true)
                .failureUrl("/login?error=true")
            )
            .logout(logout -> logout
                .logoutSuccessUrl("/")
                .invalidateHttpSession(true)
                .clearAuthentication(true)
                .deleteCookies("JSESSIONID")
            )
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                .maximumSessions(1)
                .expiredUrl("/login?expired=true")
            );
        
        return http.build();
    }

    @Bean
    public OAuth2AuthorizedClientManager authorizedClientManager(
            ClientRegistrationRepository clientRegistrationRepository,
            OAuth2AuthorizedClientRepository authorizedClientRepository) {
        
        OAuth2AuthorizedClientProvider authorizedClientProvider =
            OAuth2AuthorizedClientProviderBuilder.builder()
                .authorizationCode()
                .refreshToken()
                .build();

        DefaultOAuth2AuthorizedClientManager authorizedClientManager =
            new DefaultOAuth2AuthorizedClientManager(
                clientRegistrationRepository,
                authorizedClientRepository);
        
        authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);
        
        return authorizedClientManager;
    }
}
```

**RestClient with OAuth2 Token Propagation:**
```java
@Service
public class EmployeeClient {

    private final WebClient webClient;

    public EmployeeClient(OAuth2AuthorizedClientManager authorizedClientManager) {
        ServletOAuth2AuthorizedClientExchangeFilterFunction oauth2 =
            new ServletOAuth2AuthorizedClientExchangeFilterFunction(
                authorizedClientManager);
        
        oauth2.setDefaultClientRegistrationId("keycloak");

        this.webClient = WebClient.builder()
            .baseUrl("http://localhost:8080")
            .apply(oauth2.oauth2Configuration())
            .build();
    }

    public List<EmployeeDto> getAllEmployees() {
        return webClient.get()
            .uri("/api/employees")
            .retrieve()
            .bodyToMono(new ParameterizedTypeReference<List<EmployeeDto>>() {})
            .block();
    }

    public EmployeeDto createEmployee(CreateEmployeeRequest request) {
        return webClient.post()
            .uri("/api/employees")
            .bodyValue(request)
            .retrieve()
            .bodyToMono(EmployeeDto.class)
            .block();
    }
}
```

**Controller with OAuth2 User Info:**
```java
@Controller
public class EmployeeViewController {

    @Autowired
    private EmployeeClient employeeClient;

    @GetMapping("/employees")
    public String listEmployees(
            Model model,
            @AuthenticationPrincipal OAuth2User principal) {
        
        // Access user information
        String name = principal.getAttribute("name");
        String email = principal.getAttribute("email");
        List<String> roles = principal.getAttribute("realm_access.roles");
        
        model.addAttribute("username", name);
        model.addAttribute("employees", employeeClient.getAllEmployees());
        model.addAttribute("isAdmin", roles != null && roles.contains("ADMIN"));
        
        return "employees/list";
    }
}
```

#### Example 3: Custom JWT Token Validation

**CustomJwtValidator.java:**
```java
@Component
public class CustomJwtValidator implements OAuth2TokenValidator<Jwt> {

    @Override
    public OAuth2TokenValidatorResult validate(Jwt jwt) {
        List<OAuth2Error> errors = new ArrayList<>();

        // Validate token expiration with clock skew
        Instant expiresAt = jwt.getExpiresAt();
        if (expiresAt != null && Instant.now().isAfter(expiresAt.plusSeconds(60))) {
            errors.add(new OAuth2Error("invalid_token", "Token has expired", null));
        }

        // Validate audience
        List<String> audience = jwt.getAudience();
        if (audience == null || !audience.contains("employees-app")) {
            errors.add(new OAuth2Error("invalid_token", 
                "Token does not contain required audience", null));
        }

        // Validate issuer
        String issuer = jwt.getIssuer().toString();
        if (!issuer.equals("http://localhost:8080/realms/training-realm")) {
            errors.add(new OAuth2Error("invalid_token", 
                "Token issuer is invalid", null));
        }

        // Custom business rule: check email verification
        Boolean emailVerified = jwt.getClaim("email_verified");
        if (emailVerified == null || !emailVerified) {
            errors.add(new OAuth2Error("invalid_token", 
                "Email must be verified", null));
        }

        return errors.isEmpty() 
            ? OAuth2TokenValidatorResult.success() 
            : OAuth2TokenValidatorResult.failure(errors);
    }
}

@Configuration
public class JwtConfig {

    @Bean
    public JwtDecoder jwtDecoder(
            CustomJwtValidator customJwtValidator,
            @Value("${spring.security.oauth2.resourceserver.jwt.jwk-set-uri}") 
            String jwkSetUri) {
        
        NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withJwkSetUri(jwkSetUri).build();
        
        OAuth2TokenValidator<Jwt> validators = new DelegatingOAuth2TokenValidator<>(
            JwtValidators.createDefault(),
            customJwtValidator
        );
        
        jwtDecoder.setJwtValidator(validators);
        
        return jwtDecoder;
    }
}
```

#### Example 4: Testing Security with Spring Security Test

**EmployeeControllerTest.java:**
```java
@WebMvcTest(EmployeeController.class)
@Import(SecurityConfig.class)
class EmployeeControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private EmployeeService employeeService;

    @Test
    @WithMockUser(roles = "USER")
    void testGetAllEmployees_WithUserRole_ShouldSucceed() throws Exception {
        List<EmployeeDto> employees = Arrays.asList(
            new EmployeeDto(1L, "John Doe", "john@example.com")
        );
        
        when(employeeService.findAll()).thenReturn(employees);

        mockMvc.perform(get("/api/employees"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$[0].name").value("John Doe"));
    }

    @Test
    @WithMockUser(roles = "USER")
    void testCreateEmployee_WithUserRole_ShouldFail() throws Exception {
        CreateEmployeeRequest request = new CreateEmployeeRequest("Jane Doe", 
            "jane@example.com");

        mockMvc.perform(post("/api/employees")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
            .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    void testCreateEmployee_WithAdminRole_ShouldSucceed() throws Exception {
        CreateEmployeeRequest request = new CreateEmployeeRequest("Jane Doe", 
            "jane@example.com");
        EmployeeDto created = new EmployeeDto(2L, "Jane Doe", "jane@example.com");
        
        when(employeeService.create(any(), any())).thenReturn(created);

        mockMvc.perform(post("/api/employees")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
            .andExpect(status().isCreated())
            .andExpect(jsonPath("$.name").value("Jane Doe"));
    }

    @Test
    void testGetAllEmployees_Unauthenticated_ShouldFail() throws Exception {
        mockMvc.perform(get("/api/employees"))
            .andExpect(status().isUnauthorized());
    }
}
```

**Integration Test with Real JWT:**
```java
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
class EmployeeControllerIntegrationTest {

    @Autowired
    private TestRestTemplate restTemplate;

    @Test
    void testWithRealJwtToken() {
        // Obtain token from Keycloak (using Resource Owner Password Credentials)
        String token = getKeycloakToken("john.doe", "password123");

        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);
        
        HttpEntity<String> entity = new HttpEntity<>(headers);

        ResponseEntity<EmployeeDto[]> response = restTemplate.exchange(
            "/api/employees",
            HttpMethod.GET,
            entity,
            EmployeeDto[].class
        );

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotEmpty();
    }

    private String getKeycloakToken(String username, String password) {
        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("grant_type", "password");
        formData.add("client_id", "employees-app");
        formData.add("client_secret", "your-client-secret");
        formData.add("username", username);
        formData.add("password", password);

        RestTemplate keycloakClient = new RestTemplate();
        String tokenUrl = "http://localhost:8080/realms/training-realm/protocol/openid-connect/token";
        
        ResponseEntity<Map> response = keycloakClient.postForEntity(
            tokenUrl,
            formData,
            Map.class
        );

        return (String) response.getBody().get("access_token");
    }
}
```

### Keycloak Advanced Features

#### Custom Authentication Flow

Keycloak allows customization of authentication flows:

1. **Conditional OTP** - Require MFA only for sensitive operations
2. **Risk-Based Authentication** - Adjust security based on user behavior
3. **Custom Authenticators** - Implement custom authentication logic

**Example: Conditional OTP Configuration**
```
Authentication → Flows → Browser Flow → Duplicate
- Add Execution: Conditional OTP
- Configure: Require OTP for role "ADMIN"
```

#### Event Listeners and Audit Logging

```java
@Provider
public class CustomEventListenerProvider implements EventListenerProvider {

    @Override
    public void onEvent(Event event) {
        if (event.getType() == EventType.LOGIN) {
            log.info("User {} logged in from {}", 
                event.getUserId(), event.getIpAddress());
        } else if (event.getType() == EventType.LOGIN_ERROR) {
            log.warn("Failed login attempt for {} from {}", 
                event.getDetails().get("username"), event.getIpAddress());
        }
    }

    @Override
    public void onEvent(AdminEvent adminEvent, boolean includeRepresentation) {
        log.info("Admin action: {} on resource {}", 
            adminEvent.getOperationType(), adminEvent.getResourcePath());
    }
}
```

#### User Storage SPI (Custom User Federation)

```java
public class CustomUserStorageProvider implements UserStorageProvider, 
        UserLookupProvider, CredentialInputValidator {

    @Override
    public UserModel getUserByUsername(String username, RealmModel realm) {
        // Query custom database or external system
        User externalUser = externalUserService.findByUsername(username);
        
        if (externalUser != null) {
            return new CustomUserAdapter(session, realm, model, externalUser);
        }
        
        return null;
    }

    @Override
    public boolean isValid(RealmModel realm, UserModel user, 
            CredentialInput credentialInput) {
        
        if (!(credentialInput instanceof UserCredentialModel)) {
            return false;
        }
        
        UserCredentialModel cred = (UserCredentialModel) credentialInput;
        
        // Validate against external system
        return externalUserService.validatePassword(
            user.getUsername(), 
            cred.getValue()
        );
    }
}
```

## Employee Management Projects

This section covers **six** Spring Boot applications that demonstrate real-world web application architecture, from REST APIs to full-stack web applications with different deployment patterns and security configurations.

### Architecture Overview

These six projects showcase different architectural patterns and security approaches for building employee management systems:

```
┌─────────────────────────────────────────────────────────────────┐
│                    Architecture Comparison                       │
└─────────────────────────────────────────────────────────────────┘

BASIC APPLICATIONS (No OAuth2)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

employees-backend (Microservice Pattern)
├── REST API only (no UI)
├── Stateless backend
├── Database: PostgreSQL
├── API Endpoints: /api/employees/*
├── Security: None (demo purposes)
└── Port: 8080

employees-frontend (Separation of Concerns)
├── Web UI (Thymeleaf templates)
├── HTTP client for backend API
├── Calls employees-backend via REST
├── Database: None (stateless)
├── Security: None (demo purposes)
└── Port: 8081

employees-standalone-form (Monolithic Pattern)
├── Full stack: UI + Business Logic + Database
├── Single deployable JAR
├── Embedded forms with direct database access
├── Database: PostgreSQL
├── Security: None (demo purposes)
└── Port: 8080

OAUTH2 / OPENID CONNECT APPLICATIONS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

employees-backend-oauth2 (Resource Server)
├── REST API with OAuth 2.0 JWT validation
├── Validates access tokens from Keycloak
├── Role-based access control
├── Database: PostgreSQL
├── Security: OAuth 2.0 Resource Server
└── Port: 8080

employees-frontend-oauth2 (OAuth2 Client)
├── Web UI with OAuth 2.0 login
├── Integrates with Keycloak for authentication
├── Calls employees-backend-oauth2 with tokens
├── Database: None (stateless)
├── Security: OAuth 2.0 Client (Authorization Code Flow)
└── Port: 8080

SPRING SECURITY FORM-BASED AUTHENTICATION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

employees-standalone-form-spring-security (Form Login + RBAC)
├── Full stack with Spring Security
├── Form-based authentication
├── Role-based authorization (USER, ADMIN)
├── Password hashing with Argon2
├── Database: PostgreSQL (users + employees)
├── Security: Spring Security with form login
└── Port: 8080
```

**Comprehensive Comparison:**

| Aspect             | employees-backend   | employees-frontend | employees-standalone-form | employees-backend-oauth2  | employees-frontend-oauth2 | employees-standalone-form-spring-security |
|--------------------|---------------------|--------------------|---------------------------|---------------------------|---------------------------|-------------------------------------------|
| **Architecture**   | Microservice        | Frontend tier      | Monolithic                | Microservice              | Frontend tier             | Monolithic                                |
| **UI**             | None                | Thymeleaf          | Thymeleaf                 | None                      | Thymeleaf                 | Thymeleaf                                 |
| **Database**       | PostgreSQL          | None               | PostgreSQL                | PostgreSQL                | None                      | PostgreSQL                                |
| **Security**       | None                | None               | None                      | OAuth 2.0 Resource Server | OAuth 2.0 Client          | Spring Security Form Login                |
| **Authentication** | N/A                 | N/A                | N/A                       | JWT tokens from Keycloak  | OAuth2 Authorization Code | Username/Password (Argon2)                |
| **Authorization**  | N/A                 | N/A                | N/A                       | Role-based (JWT claims)   | Delegated to Keycloak     | Role-based (@Secured)                     |
| **Port**           | 8080                | 8081               | 8080                      | 8080                      | 8080                      | 8080                                      |
| **Use Case**       | API for mobile apps | Web UI for backend | Prototype, small apps     | Secure microservice API   | Enterprise web app        | Traditional web app with auth             |
| **Scalability**    | High                | Medium             | Low                       | High                      | Medium                    | Low                                       |
| **Complexity**     | Low                 | Low                | Low                       | Medium                    | Medium                    | Medium                                    |

### employees-backend

**Directory:** `employees-backend/`

A RESTful API backend for managing employees. This is a pure backend service with no UI, designed to be consumed by multiple frontend applications.

**Technologies:**
- Spring Boot 3.5.8
- Spring Data JPA (database access)
- Spring Validation
- PostgreSQL (database)
- Liquibase (database migrations)
- Lombok (code generation)

**Key Features:**

1. **REST API Endpoints**
   - `GET /api/employees` - List all employees
   - `GET /api/employees/{id}` - Get employee by ID
   - `POST /api/employees` - Create new employee
   - `PUT /api/employees/{id}` - Update employee
   - `DELETE /api/employees/{id}` - Delete employee

2. **Database Layer**
   - JPA Entity: `Employee`
   - Repository: `EmployeesRepository` (Spring Data)
   - Migrations: Liquibase changesets in `db/changelog/`

3. **Business Logic**
   - Service class: `EmployeesService`
   - Encapsulates business operations
   - Transaction management

4. **API Contract**
   - `EmployeeResource` - DTO for API responses
   - Request/response validation
   - Consistent error handling

5. **Exception Handling**
   - `EmployeeNotFoundException` - Custom exception for missing resources
   - `EmployeesExceptionHandler` - Global exception handler
   - `Violation` - Validation error details
   - HTTP 404, 400, 500 responses

**Database Schema (Managed by Liquibase):**

```sql
CREATE TABLE employees (
    id BIGINT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE,
    department VARCHAR(255),
    salary DECIMAL(10, 2),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

**Configuration (application.properties):**

```properties
spring.application.name=employees-backend
server.port=8080

# Database
spring.datasource.url=jdbc:postgresql://localhost:5432/employees
spring.datasource.username=postgres
spring.datasource.password=postgres
spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.PostgreSQLDialect
spring.jpa.hibernate.ddl-auto=validate

# Liquibase
spring.liquibase.enabled=true
spring.liquibase.change-log=classpath:db/changelog/db.changelog-master.xml
```

**Example API Usage:**

```bash
# Create employee
curl -X POST http://localhost:8080/api/employees \
  -H "Content-Type: application/json" \
  -d '{"name":"John Doe","email":"john@example.com","department":"IT"}'

# Get employee
curl http://localhost:8080/api/employees/1

# Update employee
curl -X PUT http://localhost:8080/api/employees/1 \
  -H "Content-Type: application/json" \
  -d '{"name":"Jane Doe","department":"HR"}'

# Delete employee
curl -X DELETE http://localhost:8080/api/employees/1
```

**Running employees-backend:**

```cmd
cd employees-backend
mvn spring-boot:run

# Or with Maven wrapper
./mvnw spring-boot:run
```

**Testing the API:**

```cmd
# Check if service is running
curl http://localhost:8080/api/employees

# Check actuator endpoints
curl http://localhost:8080/actuator/health
```

### employees-frontend

**Directory:** `employees-frontend/`

A web-based frontend application that consumes the employees-backend REST API. This demonstrates the separation of concerns pattern with independent backend and frontend services.

**Technologies:**
- Spring Boot 3.5.8
- Spring Web (MVC)
- Spring Actuator (monitoring)
- Thymeleaf (server-side templating)
- RestTemplate or WebClient (HTTP client)
- Lombok (code generation)

**Key Features:**

1. **Web UI Controller**
   - Renders HTML templates with Thymeleaf
   - Handles form submissions
   - Model-View-Controller pattern

2. **REST Client**
   - `EmployeesClient` - Communicates with backend API
   - HTTP error handling
   - Response mapping to DTOs

3. **Configuration Management**
   - `EmployeesProperties` - Configuration properties
   - `ClientConfig` - HTTP client setup (timeouts, retries)
   - Configurable backend URL

4. **Thymeleaf Templates**
   - `index.html` - Employee list view
   - `create.html` - Create employee form
   - `edit.html` - Edit employee form

5. **Static Assets**
   - CSS for styling
   - Bootstrap integration (optional)
   - JavaScript for interactivity

**Configuration (application.properties):**

```properties
spring.application.name=employees-frontend
server.port=8081

# Backend API configuration
employees.api.url=http://localhost:8080/api

# HTTP client timeouts
spring.http.client.read-timeout=5000
spring.http.client.connect-timeout=5000

# Actuator
management.endpoints.web.exposure.include=health,info
```

**File Structure:**

```
src/main/resources/
├── templates/
│   ├── index.html          # List employees
│   ├── create.html         # Create form
│   └── edit.html           # Edit form
└── static/
    ├── css/
    │   └── style.css       # Custom styling
    └── js/
        └── app.js          # Client-side JavaScript
```

**EmployeesClient Implementation Example:**

```java
@Service
public class EmployeesClient {
    
    private final RestTemplate restTemplate;
    private final EmployeesProperties properties;
    
    public List<Employee> getAllEmployees() {
        return restTemplate.getForObject(
            properties.getApiUrl() + "/employees",
            List.class
        );
    }
    
    public Employee getEmployee(Long id) {
        return restTemplate.getForObject(
            properties.getApiUrl() + "/employees/" + id,
            Employee.class
        );
    }
    
    public Employee createEmployee(Employee employee) {
        return restTemplate.postForObject(
            properties.getApiUrl() + "/employees",
            employee,
            Employee.class
        );
    }
    
    // Update and delete methods...
}
```

**Benefits of This Pattern:**

✅ **Separation of Concerns** - Frontend and backend can be developed independently
✅ **Scalability** - Each service can be scaled separately
✅ **Technology Flexibility** - Frontend can use different tech stack
✅ **Multiple Consumers** - Backend API can be used by mobile apps, other services
✅ **Testing** - Can test frontend against mock API
✅ **Deployment** - Independent deployment pipelines

**Running employees-frontend:**

```cmd
cd employees-frontend
mvn spring-boot:run

# Access at http://localhost:8081
```

**Running Both Services Together:**

```cmd
# Terminal 1: Start backend
cd employees-backend
mvn spring-boot:run

# Terminal 2: Start frontend
cd employees-frontend
mvn spring-boot:run

# Access frontend at http://localhost:8081
```

### employees-standalone-form

**Directory:** `employees-standalone-form/`

A monolithic Spring Boot application combining UI, business logic, and database in a single deployable unit. This is suitable for prototypes, small applications, or when separation of concerns is not yet necessary.

**Technologies:**
- Spring Boot 3.5.8
- Spring Web (MVC)
- Spring Data JPA (database access)
- Spring Validation
- Thymeleaf (server-side templating)
- PostgreSQL (database)
- Liquibase (database migrations)
- Lombok (code generation)

**Key Features:**

1. **Embedded Database Layer**
   - JPA Entity: `Employee`
   - Repository: `EmployeesRepository`
   - Direct database access (no external API calls)

2. **Service Layer**
   - `EmployeesService` - Business logic
   - Transaction management
   - Data validation

3. **Web UI with Forms**
   - Server-side form rendering
   - Direct form submission to backend
   - No external API calls

4. **Thymeleaf Templates with Forms**
   - `index.html` - Employee list with inline edit/delete
   - `create.html` - Create employee form
   - Form binding with Spring

5. **Database Integration**
   - Liquibase migrations
   - Automatic database initialization
   - Schema versioning

6. **Exception Handling**
   - `EmployeeNotFoundException`
   - Form validation errors
   - User-friendly error messages

**Database Schema:**

```sql
CREATE TABLE employees (
    id BIGINT PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE,
    department VARCHAR(255),
    salary DECIMAL(10, 2),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

**Configuration (application.properties):**

```properties
spring.application.name=employees-standalone
server.port=8080

# Database
spring.datasource.url=jdbc:postgresql://localhost:5432/employees_standalone
spring.datasource.username=postgres
spring.datasource.password=postgres
spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.PostgreSQLDialect
spring.jpa.hibernate.ddl-auto=validate

# Liquibase
spring.liquibase.enabled=true
spring.liquibase.change-log=classpath:db/changelog/db.changelog-master.xml

# Thymeleaf
spring.thymeleaf.cache=false
spring.thymeleaf.enabled=true
```

**Form Binding Example (Thymeleaf):**

```html
<!-- create.html -->
<form th:action="@{/employees}" method="post" th:object="${employee}">
    <input type="text" th:field="*{name}" required>
    <input type="email" th:field="*{email}" required>
    <input type="text" th:field="*{department}">
    <button type="submit">Create Employee</button>
</form>
```

**Controller Example:**

```java
@Controller
@RequestMapping("/employees")
public class EmployeesController {
    
    @GetMapping
    public String list(Model model) {
        model.addAttribute("employees", service.getAllEmployees());
        return "index";
    }
    
    @PostMapping
    public String create(@ModelAttribute("employee") Employee employee) {
        service.createEmployee(employee);
        return "redirect:/employees";
    }
    
    // Edit and delete methods...
}
```

**Benefits of This Pattern:**

✅ **Simple Deployment** - Single JAR file
✅ **Quick Development** - Monolithic structure for rapid prototyping
✅ **Direct Database Access** - No network latency
✅ **Lower Complexity** - Fewer moving parts
✅ **Easier Debugging** - Everything in one process
❌ **Limited Scalability** - Can't scale frontend/backend independently
❌ **Technology Lock-in** - Must use compatible technologies

**Running employees-standalone-form:**

```cmd
cd employees-standalone-form
mvn spring-boot:run

# Access at http://localhost:8080
```

### Deployment Patterns

**Pattern 1: Microservices (Backend + Frontend)**

```
┌─────────────────────────────────────────────┐
│ Client (Browser)                            │
└─────────────────────────────────────────────┘
         ↓
┌─────────────────────────────────────────────┐
│ employees-frontend (Port 8081)              │
│ Thymeleaf UI + RestTemplate                 │
└─────────────────────────────────────────────┘
         ↓
┌─────────────────────────────────────────────┐
│ employees-backend (Port 8080)               │
│ REST API + JPA + PostgreSQL                 │
└─────────────────────────────────────────────┘
```

**Benefits:**
- Independent scaling
- Different deployment schedules
- Multiple clients (web, mobile, etc.)
- Technology flexibility

**Deployment:**
```cmd
# Backend (data center)
cd employees-backend && mvn spring-boot:run

# Frontend (web tier)
cd employees-frontend && mvn spring-boot:run
```

**Pattern 2: Monolithic (Standalone)**

```
┌─────────────────────────────────────────────┐
│ Client (Browser)                            │
└─────────────────────────────────────────────┘
         ↓
┌─────────────────────────────────────────────┐
│ employees-standalone-form (Port 8080)       │
│ Thymeleaf UI + JPA + PostgreSQL             │
└─────────────────────────────────────────────┘
```

**Benefits:**
- Simple deployment
- Fewer moving parts
- Quick development

**Deployment:**
```cmd
cd employees-standalone-form && mvn spring-boot:run
```

---

### employees-backend-oauth2

**Directory:** `employees-backend-oauth2/`

A secured RESTful API backend that validates OAuth 2.0 JWT access tokens issued by Keycloak. This is a **Resource Server** implementation following OAuth 2.0 specifications.

**Technologies:**
- Spring Boot 3.5.8
- Spring Security OAuth2 Resource Server
- Spring Data JPA
- PostgreSQL
- Liquibase
- Lombok

**Key Features:**

1. **OAuth 2.0 Resource Server**
   - Validates JWT access tokens from Keycloak
   - Extracts user information from token claims
   - Verifies token signature using Keycloak's public key
   - Checks token expiration and issuer

2. **Role-Based Access Control (RBAC)**
   - Roles extracted from JWT `realm_access.roles` claim
   - Method-level security with `@PreAuthorize`
   - Fine-grained authorization for endpoints

3. **REST API Endpoints**
   - `GET /api/employees` - List all employees (requires `USER` or `ADMIN` role)
   - `GET /api/employees/{id}` - Get employee by ID (requires authentication)
   - `POST /api/employees` - Create new employee (requires `ADMIN` role)
   - `PUT /api/employees/{id}` - Update employee (requires `ADMIN` role)
   - `DELETE /api/employees/{id}` - Delete employee (requires `ADMIN` role)

4. **Security Configuration**
   ```java
   @Configuration
   @EnableWebSecurity
   @EnableMethodSecurity
   public class SecurityConfig {
       @Bean
       public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
           http
               .authorizeHttpRequests(authz -> authz
                   .requestMatchers("/api/public/**").permitAll()
                   .requestMatchers("/api/employees/**").authenticated()
                   .anyRequest().denyAll()
               )
               .oauth2ResourceServer(oauth2 -> oauth2.jwt())
               .sessionManagement(session -> session
                   .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
               )
               .csrf(csrf -> csrf.disable());
           return http.build();
       }
   }
   ```

**Configuration (application.yaml):**

```yaml
spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          issuer-uri: http://localhost:8090/realms/EmployeesRealm
          jwk-set-uri: http://localhost:8090/realms/EmployeesRealm/protocol/openid-connect/certs

  datasource:
    url: jdbc:postgresql://localhost:5432/employees
    username: employees
    password: employees

server:
  port: 8080
```

**JWT Token Structure:**

```json
{
  "exp": 1701878400,
  "iat": 1701878100,
  "jti": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "iss": "http://localhost:8090/realms/EmployeesRealm",
  "aud": "account",
  "sub": "12345678-1234-1234-1234-123456789012",
  "typ": "Bearer",
  "azp": "employees-frontend",
  "realm_access": {
    "roles": ["USER", "ADMIN"]
  },
  "email": "john.doe@example.com",
  "name": "John Doe",
  "preferred_username": "john.doe"
}
```

**Example API Usage with Token:**

```bash
# Obtain token from Keycloak (using password grant for testing)
TOKEN=$(curl -X POST http://localhost:8090/realms/EmployeesRealm/protocol/openid-connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=employees-frontend" \
  -d "username=john.doe" \
  -d "password=password123" \
  | jq -r '.access_token')

# Call API with token
curl -X GET http://localhost:8080/api/employees \
  -H "Authorization: Bearer $TOKEN"

# Create employee (requires ADMIN role)
curl -X POST http://localhost:8080/api/employees \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"Jane Doe","email":"jane@example.com"}'
```

**Running employees-backend-oauth2:**

```cmd
# Ensure Keycloak is running on port 8090
cd employees-backend-oauth2
mvn spring-boot:run
```

**Security Features:**
- ✅ Stateless authentication (no session)
- ✅ JWT signature verification
- ✅ Token expiration checking
- ✅ Issuer validation
- ✅ Role-based authorization
- ✅ CORS configuration for frontend
- ✅ Protection against common attacks (XSS, CSRF not needed for stateless API)

---

### employees-frontend-oauth2

**Directory:** `employees-frontend-oauth2/`

A web frontend application that integrates with Keycloak for authentication using **OAuth 2.0 Authorization Code Flow**. This is an **OAuth2 Client** implementation.

**Technologies:**
- Spring Boot 3.5.8
- Spring Security OAuth2 Client
- Thymeleaf (server-side templates)
- WebClient (for REST calls)
- OAuth2 Authorization Code Flow with PKCE

**Key Features:**

1. **OAuth 2.0 Client**
   - Implements Authorization Code Flow
   - PKCE (Proof Key for Code Exchange) support
   - Automatic token refresh
   - Session-based token storage

2. **Keycloak Integration**
   - Redirects to Keycloak for login
   - Handles OAuth2 callback
   - Stores tokens in HTTP session
   - Single Sign-On (SSO) support

3. **Backend API Integration**
   - Calls `employees-backend-oauth2` REST API
   - Propagates access token to backend
   - Handles token expiration and refresh
   - Automatic authentication retry

4. **User Interface**
   - Login page (redirects to Keycloak)
   - Employee list page
   - Create employee form (ADMIN only)
   - User profile display
   - Logout functionality

**Configuration (application.yaml):**

```yaml
spring:
  security:
    oauth2:
      client:
        registration:
          keycloak:
            client-id: employees-frontend
            authorization-grant-type: authorization_code
            scope:
              - openid
              - profile
              - email
        provider:
          keycloak:
            issuer-uri: http://localhost:8090/realms/EmployeesRealm

server:
  port: 8080
```

**Security Configuration:**

```java
@Configuration
public class SecurityConfig {
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(authz -> authz
                .requestMatchers("/create-employee").authenticated()
                .anyRequest().permitAll()
            )
            .oauth2Login(withDefaults())
            .logout(withDefaults());
        return http.build();
    }
}
```

**OAuth2 Flow in This Application:**

1. **User accesses protected page** → Redirected to Keycloak
2. **User logs in at Keycloak** → Keycloak authenticates user
3. **Keycloak redirects back** → With authorization code
4. **Application exchanges code for tokens** → Receives access_token, id_token, refresh_token
5. **Tokens stored in session** → Secure, HttpOnly cookies
6. **API calls include access token** → Backend validates token
7. **Token expires** → Automatically refreshed using refresh_token

**Controller Example:**

```java
@Controller
public class EmployeesController {
    
    @Autowired
    private EmployeesClient employeesClient;

    @GetMapping("/employees")
    public String listEmployees(
            Model model,
            @AuthenticationPrincipal OAuth2User principal) {
        
        // Get user info from token
        String name = principal.getAttribute("name");
        List<String> roles = principal.getAttribute("realm_access.roles");
        
        // Call backend API (token automatically included)
        List<EmployeeDto> employees = employeesClient.getAllEmployees();
        
        model.addAttribute("username", name);
        model.addAttribute("employees", employees);
        model.addAttribute("isAdmin", roles.contains("ADMIN"));
        
        return "employees/list";
    }

    @PostMapping("/create-employee")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public String createEmployee(@ModelAttribute EmployeeRequest request) {
        employeesClient.createEmployee(request);
        return "redirect:/employees";
    }
}
```

**WebClient with OAuth2 Token Propagation:**

```java
@Service
public class EmployeesClient {
    
    private final WebClient webClient;

    public EmployeesClient(OAuth2AuthorizedClientManager authorizedClientManager) {
        ServletOAuth2AuthorizedClientExchangeFilterFunction oauth2 =
            new ServletOAuth2AuthorizedClientExchangeFilterFunction(
                authorizedClientManager);
        
        oauth2.setDefaultClientRegistrationId("keycloak");

        this.webClient = WebClient.builder()
            .baseUrl("http://localhost:8080")
            .apply(oauth2.oauth2Configuration())
            .build();
    }

    public List<EmployeeDto> getAllEmployees() {
        return webClient.get()
            .uri("/api/employees")
            .retrieve()
            .bodyToFlux(EmployeeDto.class)
            .collectList()
            .block();
    }
}
```

**Running employees-frontend-oauth2:**

```cmd
# Ensure Keycloak is running on port 8090
# Ensure employees-backend-oauth2 is running on port 8080
cd employees-frontend-oauth2
mvn spring-boot:run
```

**Access:** http://localhost:8080

**Login Flow:**
1. Navigate to http://localhost:8080/employees
2. Redirected to Keycloak login page
3. Enter credentials (e.g., john.doe / password123)
4. Redirected back to application
5. See employee list with user name displayed

**Security Features:**
- ✅ Authorization Code Flow with PKCE
- ✅ Secure token storage (server-side session)
- ✅ Automatic token refresh
- ✅ CSRF protection enabled
- ✅ HttpOnly session cookies
- ✅ State parameter for CSRF prevention
- ✅ Single Sign-On (SSO) support

---

### employees-standalone-form-spring-security

**Directory:** `employees-standalone-form-spring-security/`

A monolithic application with traditional **Spring Security form-based authentication**. This demonstrates role-based access control without OAuth2, using database-stored user credentials.

**Technologies:**
- Spring Boot 3.5.8
- Spring Security (Form Login)
- Spring Data JPA
- PostgreSQL
- Liquibase
- Thymeleaf
- Argon2 password hashing

**Key Features:**

1. **Form-Based Authentication**
   - Traditional username/password login
   - Login page with CSRF protection
   - Remember-me functionality
   - Logout support

2. **Password Security**
   - Argon2 password hashing (OWASP recommended)
   - Strong password encoding
   - Secure password storage in database

3. **Role-Based Authorization**
   - `USER` role - Can view employees
   - `ADMIN` role - Can create/edit/delete employees
   - Method-level security with `@Secured`
   - URL-based authorization

4. **User Management**
   - Users stored in database
   - Roles assigned to users
   - User details service for authentication

**Database Schema:**

```sql
-- Users table
CREATE TABLE users (
    username VARCHAR(50) PRIMARY KEY,
    password VARCHAR(100) NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE
);

-- Authorities (roles) table
CREATE TABLE authorities (
    username VARCHAR(50) NOT NULL,
    authority VARCHAR(50) NOT NULL,
    CONSTRAINT fk_authorities_users 
        FOREIGN KEY(username) 
        REFERENCES users(username),
    CONSTRAINT authorities_idx 
        UNIQUE (username, authority)
);

-- Employees table
CREATE TABLE employees (
    id BIGINT PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE
);
```

**Security Configuration:**

```java
@Configuration
@EnableMethodSecurity(securedEnabled = true)
public class SecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(registry -> registry
                .requestMatchers("/login").permitAll()
                .requestMatchers("/", "/employees").hasRole("USER")
                .requestMatchers("/create-employee").hasRole("ADMIN")
                .anyRequest().denyAll()
            )
            .formLogin(Customizer.withDefaults())
            .logout(Customizer.withDefaults());
        return http.build();
    }
}
```

**Configuration (application.yaml):**

```yaml
spring:
  datasource:
    url: jdbc:postgresql://localhost:5432/employees
    username: employees
    password: employees
  jpa:
    open-in-view: false
  liquibase:
    change-log: classpath:db/db-changelog.yaml

server:
  port: 8080
```

**Sample Users (Created by Liquibase):**

```sql
-- User with USER role (password: user123)
INSERT INTO users (username, password, enabled) 
VALUES ('user', '{argon2}$argon2id$v=19$m=16384,t=2,p=1$...', true);

INSERT INTO authorities (username, authority) 
VALUES ('user', 'ROLE_USER');

-- User with ADMIN role (password: admin123)
INSERT INTO users (username, password, enabled) 
VALUES ('admin', '{argon2}$argon2id$v=19$m=16384,t=2,p=1$...', true);

INSERT INTO authorities (username, authority) 
VALUES ('admin', 'ROLE_USER'), ('admin', 'ROLE_ADMIN');
```

**Controller with Security Annotations:**

```java
@Controller
public class EmployeesController {

    @Autowired
    private EmployeesService employeesService;

    @GetMapping("/employees")
    @Secured("ROLE_USER")
    public String listEmployees(Model model, Authentication authentication) {
        model.addAttribute("employees", employeesService.findAll());
        model.addAttribute("username", authentication.getName());
        
        // Check if user is admin
        boolean isAdmin = authentication.getAuthorities().stream()
            .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"));
        model.addAttribute("isAdmin", isAdmin);
        
        return "employees/list";
    }

    @GetMapping("/create-employee")
    @Secured("ROLE_ADMIN")
    public String createEmployeeForm(Model model) {
        model.addAttribute("employee", new CreateEmployeeCommand());
        return "employees/create";
    }

    @PostMapping("/create-employee")
    @Secured("ROLE_ADMIN")
    public String createEmployee(@Valid @ModelAttribute CreateEmployeeCommand command) {
        employeesService.create(command);
        return "redirect:/employees";
    }
}
```

**Running employees-standalone-form-spring-security:**

```cmd
# Ensure PostgreSQL is running
# Database will be created by Liquibase
cd employees-standalone-form-spring-security
mvn spring-boot:run
```

**Access:** http://localhost:8080

**Login Credentials:**
- **User:** username=`user`, password=`user123` (can view employees)
- **Admin:** username=`admin`, password=`admin123` (can create/edit/delete)

**Security Features:**
- ✅ Form-based login (Spring Security default)
- ✅ Argon2 password hashing (OWASP recommended)
- ✅ CSRF protection enabled
- ✅ Session management
- ✅ Role-based access control (RBAC)
- ✅ Method-level security (`@Secured`)
- ✅ URL-based authorization
- ✅ Logout functionality
- ✅ Authentication remembered across sessions

**Comparison with OAuth2 Approach:**

| Aspect | Form-Based (This Project) | OAuth2 (employees-frontend-oauth2) |
|--------|---------------------------|-------------------------------------|
| **Login** | Local login form | Keycloak login page |
| **Credentials** | Stored in app database | Managed by Keycloak |
| **Token** | Session cookie | JWT access token |
| **SSO** | No | Yes (across apps) |
| **Scalability** | Limited (session state) | High (stateless tokens) |
| **Complexity** | Low | Medium |
| **Use Case** | Small, internal apps | Enterprise, multiple apps |

---

### Database Setup

All six applications (except frontend-only ones) use PostgreSQL. Create databases before running:

```sql
-- Create databases
CREATE DATABASE employees;
CREATE DATABASE employees_standalone;

-- Create user (if needed)
CREATE USER employees WITH PASSWORD 'employees';
GRANT ALL PRIVILEGES ON DATABASE employees TO employees;
GRANT ALL PRIVILEGES ON DATABASE employees_standalone TO employees;
```

**Or using psql command line:**

```bash
psql -U postgres
```

Then:

```sql
CREATE DATABASE employees;
CREATE DATABASE employees_standalone;
```

Liquibase will automatically create tables and run migrations on application startup.

### Running the OAuth2 Applications Together

To see the complete OAuth2 flow with all components:

**1. Start Keycloak (Docker):**

```bash
docker run -p 8090:8080 \
  -e KEYCLOAK_ADMIN=admin \
  -e KEYCLOAK_ADMIN_PASSWORD=admin \
  quay.io/keycloak/keycloak:23.0.0 \
  start-dev
```

Access Keycloak Admin Console: http://localhost:8090 (admin/admin)

**2. Configure Keycloak:**
- Create realm: `EmployeesRealm`
- Create client: `employees-frontend` (OAuth2 client)
- Create roles: `USER`, `ADMIN`
- Create users with roles

**3. Start Backend Resource Server:**

```cmd
cd employees-backend-oauth2
mvn spring-boot:run
```

**4. Start Frontend OAuth2 Client:**

```cmd
cd employees-frontend-oauth2
mvn spring-boot:run
```

**5. Access Application:**
- Navigate to http://localhost:8080
- Click login → Redirected to Keycloak
- Login with Keycloak user
- Access employee management features

### Running All Applications

**Terminal 1: Start Backend**

```cmd
cd employees-backend
mvn spring-boot:run
```

**Terminal 2: Start Frontend**

```cmd
cd employees-frontend
mvn spring-boot:run
```

**Terminal 3: Start Standalone (optional)**

```cmd
cd employees-standalone-form
mvn spring-boot:run
```

**Terminal 4: Start OAuth2 Backend (optional)**

```cmd
cd employees-backend-oauth2
mvn spring-boot:run
```

**Terminal 5: Start OAuth2 Frontend (optional)**

```cmd
cd employees-frontend-oauth2
mvn spring-boot:run
```

**Terminal 6: Start Spring Security Standalone (optional)**

```cmd
cd employees-standalone-form-spring-security
mvn spring-boot:run
```

**Access Points:**
- employees-backend API: http://localhost:8080/api/employees
- employees-frontend UI: http://localhost:8081
- employees-standalone UI: http://localhost:8080
- employees-backend-oauth2 API: http://localhost:8080/api/employees (requires token)
- employees-frontend-oauth2 UI: http://localhost:8080
- employees-standalone-form-spring-security UI: http://localhost:8080 (login with user/admin)

### Learning Outcomes

These six projects demonstrate:

**Basic Architecture Patterns:**
1. **REST API Design** - employees-backend
2. **HTTP Client Integration** - employees-frontend
3. **Separation of Concerns** - Backend/Frontend pattern
4. **Monolithic Architecture** - Standalone pattern
5. **Database Migration** - Liquibase in all projects
6. **Spring MVC & Thymeleaf** - Web UI development
7. **Error Handling** - Custom exceptions and handlers
8. **Configuration Management** - Properties and environment variables
9. **JPA & Spring Data** - Object-relational mapping
10. **Production-Ready Code** - Validation, logging, testing

**OAuth 2.0 & OpenID Connect:**
11. **OAuth 2.0 Resource Server** - JWT token validation (employees-backend-oauth2)
12. **OAuth 2.0 Client** - Authorization Code Flow (employees-frontend-oauth2)
13. **Keycloak Integration** - Identity and Access Management
14. **JWT Token Handling** - Parsing, validation, claims extraction
15. **Token Propagation** - Forwarding tokens between services
16. **PKCE (Proof Key for Code Exchange)** - Enhanced security for OAuth2
17. **Single Sign-On (SSO)** - Unified authentication across apps
18. **Role-Based Access Control (RBAC)** - Fine-grained authorization

**Spring Security:**
19. **Form-Based Authentication** - Traditional login (employees-standalone-form-spring-security)
20. **Password Hashing** - Argon2 password encoder
21. **Method Security** - `@Secured`, `@PreAuthorize` annotations
22. **CSRF Protection** - Cross-Site Request Forgery prevention
23. **Session Management** - HttpOnly cookies, session timeout
24. **User Details Service** - Database-backed authentication

**Advanced Concepts:**
25. **Stateless vs Stateful** - Token-based vs session-based auth
26. **Microservices Security** - Service-to-service authentication
27. **API Gateway Pattern** - Centralized authentication/authorization
28. **Zero Trust Security** - Always verify, never trust
29. **Security Testing** - Unit tests with Spring Security Test
30. **Compliance** - OWASP best practices, secure coding standards

### Troubleshooting

**Issue: Port already in use**

```cmd
# Windows: Find and kill process on port 8080
netstat -ano | findstr :8080
taskkill /PID <PID> /F

# Linux/Mac: Find and kill process on port 8080
lsof -i :8080
kill -9 <PID>
```

**Issue: Database connection refused**

```
Error: Could not get a connection
```

**Solution:**
- Ensure PostgreSQL is running
- Verify database exists
- Check application.properties credentials
- Verify database URL: `jdbc:postgresql://localhost:5432/employees`

**Issue: Liquibase migration fails**

```
Error: Migration V1__initial_schema.sql failed
```

**Solution:**
- Check `db/changelog/` directory exists
- Verify Liquibase XML is valid
- Check database permissions
- Review logs for specific error

**Issue: Frontend can't connect to backend**

```
java.net.ConnectException: Connection refused
```

**Solution:**
- Ensure backend is running on correct port (8080)
- Check `employees.api.url` in frontend properties
- Verify firewall allows localhost connections
- Check backend startup logs for errors

## Running the Examples

### Using Maven (with Java 21)

Set Java 21 as Maven's JDK and run any example:

```powershell
$env:JAVA_HOME="C:\DevTools\Java\jdk-21.0.4"
cd jca
mvn clean compile

# Run specific examples
mvn exec:java -Dexec.mainClass="jca.ProvidersMain"
mvn exec:java -Dexec.mainClass="jca.HashMain"
mvn exec:java -Dexec.mainClass="jca.CipherMain"
mvn exec:java -Dexec.mainClass="jca.SignMain"
mvn exec:java -Dexec.mainClass="jca.VerifySignMain"
mvn exec:java -Dexec.mainClass="jca.CertificateMain"
```

### Using IntelliJ IDEA

1. Open the project in IntelliJ IDEA
2. Ensure JDK 21 is configured (File → Project Structure → SDK)
3. Right-click on any `Main` class → Run

### Signature Workflow Example

```powershell
# 1. Create a signature
mvn exec:java -Dexec.mainClass="jca.SignMain"
# Output: Signature written to: C:/Repos/java-sc-training-2025-12-03/signature.bin

# 2. Verify the signature
mvn exec:java -Dexec.mainClass="jca.VerifySignMain"
# Output: Valid: true
```

## Additional Reading

### Books

1. **"Cryptography Engineering"** by Niels Ferguson, Bruce Schneier, and Tadayoshi Kohno
   - Practical cryptographic system design
   - Real-world security considerations

2. **"Applied Cryptography"** by Bruce Schneier
   - Comprehensive cryptographic algorithms reference
   - Classic cryptography textbook

3. **"Serious Cryptography"** by Jean-Philippe Aumasson
   - Modern cryptographic practices
   - Beginner-friendly approach

### Online Resources

#### Official Documentation
- [Java Security Guide](https://docs.oracle.com/en/java/javase/21/security/)
- [JCA Reference Guide](https://docs.oracle.com/en/java/javase/21/security/java-cryptography-architecture-jca-reference-guide.html)
- [Bouncy Castle Documentation](https://www.bouncycastle.org/documentation.html)

#### Standards and Specifications
- [RFC 5280 - X.509 Certificates](https://tools.ietf.org/html/rfc5280)
- [RFC 2315 - PKCS #7](https://tools.ietf.org/html/rfc2315)
- [RFC 5208 - PKCS #8](https://tools.ietf.org/html/rfc5208)
- [RFC 7292 - PKCS #12](https://tools.ietf.org/html/rfc7292)
- [FIPS 140-3 - Cryptographic Standards](https://csrc.nist.gov/publications/detail/fips/140/3/final)

#### Learning Resources
- [Crypto101 - Free Cryptography Course](https://www.crypto101.io/)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [NIST Cryptographic Standards](https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines)

#### Best Practices
- [OWASP Cryptography Guide](https://owasp.org/www-community/Cryptography)
- [Google Tink - Cryptography Library](https://github.com/google/tink)
- [OWASP Key Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html)

#### Tools
- [KeyStore Explorer](https://keystore-explorer.org/) - GUI for keystore management
- [OpenSSL](https://www.openssl.org/) - Command-line cryptographic toolkit
- [Cryptool](https://www.cryptool.org/) - E-learning platform for cryptography

### Video Courses
- [Coursera - Cryptography I](https://www.coursera.org/learn/crypto) by Stanford University
- [Udemy - Complete Cryptography Course](https://www.udemy.com/topic/cryptography/)
- [Pluralsight - Java Security Fundamentals](https://www.pluralsight.com/)
- [LinkedIn Learning - Cryptography and Network Security](https://www.linkedin.com/learning/)

### Modern Security Topics

#### JWT (JSON Web Tokens)
**Reading Materials:**
- [JWT Introduction](https://jwt.io/introduction)
- [RFC 7519 - JSON Web Token](https://tools.ietf.org/html/rfc7519)
- [Auth0 JWT Handbook](https://auth0.com/resources/ebooks/jwt-handbook)
- [OWASP JWT Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)

**Key Concepts:**
- Stateless authentication mechanism
- Composed of Header, Payload, and Signature
- Used extensively in OAuth 2.0 and OpenID Connect
- Should be signed (JWS) and optionally encrypted (JWE)
- Vulnerable to algorithm confusion attacks if not validated properly

**Java Libraries:**
- [jjwt (Java JWT)](https://github.com/jwtk/jjwt) - Popular JWT library for Java
- [Nimbus JOSE + JWT](https://connect2id.com/products/nimbus-jose-jwt)
- [Auth0 Java JWT](https://github.com/auth0/java-jwt)

**Example Use Case:**
```java
// Creating a JWT with jjwt library
String jwt = Jwts.builder()
    .setSubject("user123")
    .setIssuedAt(new Date())
    .setExpiration(new Date(System.currentTimeMillis() + 3600000))
    .claim("roles", Arrays.asList("USER", "ADMIN"))
    .signWith(SignatureAlgorithm.HS256, secretKey)
    .compact();
```

#### Web Security (CSRF, XSS, CORS)

**Cross-Site Request Forgery (CSRF):**
- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [Spring Security CSRF Protection](https://docs.spring.io/spring-security/reference/features/exploits/csrf.html)
- Use synchronizer tokens or double-submit cookies
- SameSite cookie attribute helps prevent CSRF

**Cross-Site Scripting (XSS):**
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [DOMPurify](https://github.com/cure53/DOMPurify) - DOM-only XSS sanitizer
- Always sanitize user input
- Use Content Security Policy (CSP) headers
- Encode output based on context (HTML, JavaScript, URL)

**Cross-Origin Resource Sharing (CORS):**
- [CORS Specification](https://www.w3.org/TR/cors/)
- [Spring CORS Configuration](https://spring.io/guides/gs/rest-service-cors/)
- Configure allowed origins, methods, and headers
- Avoid using wildcards (*) in production

#### Password Storage and Authentication

**Modern Password Hashing:**
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- **Argon2** - Winner of Password Hashing Competition (recommended)
- **bcrypt** - Widely used, adaptive cost factor
- **scrypt** - Memory-hard function
- **PBKDF2** - NIST recommended, available in Java

**Java Libraries:**
- [Spring Security Crypto](https://docs.spring.io/spring-security/reference/features/authentication/password-storage.html)
- [Bouncy Castle - SCrypt, BCrypt](https://www.bouncycastle.org/)
- [Password4j](https://github.com/Password4j/password4j) - Modern password hashing

**Example:**
```java
// Using bcrypt with Spring Security
BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);
String hashedPassword = encoder.encode("plainPassword");
boolean matches = encoder.matches("plainPassword", hashedPassword);
```

#### Multi-Factor Authentication (MFA)

**Resources:**
- [OWASP MFA Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html)
- [RFC 6238 - TOTP](https://tools.ietf.org/html/rfc6238) - Time-based One-Time Password
- [RFC 4226 - HOTP](https://tools.ietf.org/html/rfc4226) - HMAC-based One-Time Password
- [WebAuthn](https://webauthn.io/) - Modern passwordless authentication

**Java Libraries:**
- [GoogleAuth](https://github.com/wstrange/GoogleAuth) - Google Authenticator compatible TOTP
- [TOTP-Spring-Boot-Starter](https://github.com/samdjstevens/totp-spring-boot-starter)

#### API Security

**Resources:**
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [API Security Best Practices](https://github.com/shieldfy/API-Security-Checklist)
- Rate limiting and throttling
- API key management
- OAuth 2.0 scopes and permissions
- API versioning strategies

**Key Practices:**
- Use HTTPS everywhere
- Implement proper authentication (OAuth 2.0, API keys)
- Validate and sanitize all inputs
- Implement rate limiting
- Use API gateways for centralized security
- Log and monitor API usage

### Cloud Security and Key Management

**AWS Security:**
- [AWS Key Management Service (KMS)](https://aws.amazon.com/kms/)
- [AWS Secrets Manager](https://aws.amazon.com/secrets-manager/)
- [AWS Certificate Manager](https://aws.amazon.com/certificate-manager/)
- [AWS CloudHSM](https://aws.amazon.com/cloudhsm/)

**Azure Security:**
- [Azure Key Vault](https://azure.microsoft.com/en-us/services/key-vault/)
- [Azure Managed HSM](https://docs.microsoft.com/en-us/azure/key-vault/managed-hsm/)
- [Azure Confidential Computing](https://azure.microsoft.com/en-us/solutions/confidential-compute/)

**Google Cloud Security:**
- [Google Cloud KMS](https://cloud.google.com/security-key-management)
- [Google Secret Manager](https://cloud.google.com/secret-manager)
- [Google Cloud HSM](https://cloud.google.com/kms/docs/hsm)

**HashiCorp Vault:**
- [Vault Documentation](https://www.vaultproject.io/docs)
- Dynamic secrets generation
- Encryption as a Service
- Certificate management
- Multi-cloud support

### Security Testing and Tools

**Static Analysis:**
- [SpotBugs](https://spotbugs.github.io/) - Java bug detector
- [Find Security Bugs](https://find-sec-bugs.github.io/) - SpotBugs plugin for security audits
- [SonarQube](https://www.sonarqube.org/) - Code quality and security
- [Checkmarx](https://www.checkmarx.com/) - Static Application Security Testing (SAST)

**Dependency Scanning:**
- [OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/)
- [Snyk](https://snyk.io/) - Vulnerability scanning for dependencies
- [GitHub Dependabot](https://github.com/dependabot) - Automated dependency updates
- [JFrog Xray](https://jfrog.com/xray/) - Universal artifact analysis

**Dynamic Analysis:**
- [OWASP ZAP](https://www.zaproxy.org/) - Web application security scanner
- [Burp Suite](https://portswigger.net/burp) - Web vulnerability scanner
- [Acunetix](https://www.acunetix.com/) - Automated web app security testing

**Penetration Testing:**
- [Metasploit Framework](https://www.metasploit.com/)
- [Kali Linux](https://www.kali.org/) - Penetration testing distribution
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)

### Security Frameworks and Standards

**Compliance Frameworks:**
- **PCI DSS** - Payment Card Industry Data Security Standard
- **HIPAA** - Health Insurance Portability and Accountability Act
- **GDPR** - General Data Protection Regulation
- **SOC 2** - Service Organization Control 2
- **ISO 27001** - Information Security Management
- **NIST Cybersecurity Framework**

**Resources:**
- [PCI Security Standards](https://www.pcisecuritystandards.org/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [CIS Controls](https://www.cisecurity.org/controls/)
- [SANS Security Resources](https://www.sans.org/security-resources/)

### Modern Cryptographic Trends

**Post-Quantum Cryptography:**
- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
- Preparing for quantum computing threats
- CRYSTALS-Kyber (key encapsulation)
- CRYSTALS-Dilithium (digital signatures)
- [Bouncy Castle Post-Quantum Support](https://www.bouncycastle.org/java.html)

**Zero-Knowledge Proofs:**
- [zkSNARKs](https://z.cash/technology/zksnarks/) - Zero-Knowledge Succinct Non-Interactive Arguments of Knowledge
- Privacy-preserving authentication
- Blockchain applications

**Homomorphic Encryption:**
- Computing on encrypted data without decryption
- [Microsoft SEAL](https://github.com/microsoft/SEAL)
- Privacy-preserving machine learning

### Practical Security Examples

**Example 1: Secure Configuration Management**
```java
// Using environment variables for sensitive data
String dbPassword = System.getenv("DB_PASSWORD");
String apiKey = System.getenv("API_KEY");

// Using Spring Boot externalized configuration
@ConfigurationProperties(prefix = "app.security")
public class SecurityProperties {
    private String jwtSecret;
    private int jwtExpiration;
    // getters and setters
}
```

**Example 2: Secure REST API Endpoint**
```java
@RestController
@RequestMapping("/api/employees")
public class EmployeeController {
    
    @PreAuthorize("hasRole('ADMIN')")
    @PostMapping
    public ResponseEntity<Employee> createEmployee(
            @Valid @RequestBody EmployeeRequest request) {
        // Input validation via @Valid
        // Authorization via @PreAuthorize
        // Business logic
    }
    
    @GetMapping("/{id}")
    @RateLimiter(name = "employee-api")
    public ResponseEntity<Employee> getEmployee(@PathVariable Long id) {
        // Rate limiting to prevent abuse
        // Return employee data
    }
}
```

**Example 3: Secure Password Reset Flow**
```java
// 1. Generate secure token
String resetToken = UUID.randomUUID().toString();
String hashedToken = passwordEncoder.encode(resetToken);

// 2. Store with expiration
PasswordResetToken token = new PasswordResetToken();
token.setToken(hashedToken);
token.setExpiryDate(LocalDateTime.now().plusHours(24));
token.setUser(user);
tokenRepository.save(token);

// 3. Send via secure channel (email with HTTPS link)
emailService.sendPasswordResetEmail(user.getEmail(), resetToken);

// 4. Validate token on reset
if (token.isExpired() || !passwordEncoder.matches(providedToken, token.getToken())) {
    throw new InvalidTokenException();
}
```

### Community and Forums

**Security Communities:**
- [OWASP Community](https://owasp.org/community/)
- [Security StackExchange](https://security.stackexchange.com/)
- [Reddit r/netsec](https://www.reddit.com/r/netsec/)
- [Reddit r/crypto](https://www.reddit.com/r/crypto/)

**Blogs and News:**
- [Krebs on Security](https://krebsonsecurity.com/)
- [Schneier on Security](https://www.schneier.com/)
- [The Hacker News](https://thehackernews.com/)
- [Threatpost](https://threatpost.com/)

**Podcasts:**
- [Security Now](https://twit.tv/shows/security-now)
- [Darknet Diaries](https://darknetdiaries.com/)
- [Risky Business](https://risky.biz/)

## Best Practices

### General Security
- ✅ Always use well-established cryptographic libraries (JCA, Bouncy Castle)
- ✅ Never implement your own cryptographic algorithms
- ✅ Keep cryptographic libraries up-to-date
- ✅ Use the highest security settings your application can support

### Random Number Generation
- ✅ Use `SecureRandom` for all cryptographic operations
- ✅ Consider using `SecureRandom.getInstanceStrong()` for key generation
- ✅ Cache SecureRandom instances in ThreadLocal for performance
- ❌ Never use `java.util.Random` for security purposes

### Hashing
- ✅ Use SHA-256 or stronger (SHA-384, SHA-512)
- ✅ Use constant-time comparison for hash verification
- ❌ Avoid MD5 and SHA-1 for new applications
- ✅ Use salts for password hashing (consider bcrypt, scrypt, Argon2)

### Symmetric Encryption
- ✅ Use AES with at least 256-bit keys
- ✅ Use authenticated encryption modes (GCM, EAX)
- ✅ Generate unique IVs for each encryption operation
- ✅ Never reuse IV with the same key
- ❌ Avoid ECB mode (insecure)
- ⚠️ CBC mode requires additional authentication (use HMAC)

### Asymmetric Encryption
- ✅ Use RSA with at least 2048-bit keys (3072+ for long-term)
- ✅ Consider using elliptic curve cryptography (ECC) for better performance
- ✅ Use proper padding (OAEP for encryption, PSS for signatures)
- ✅ Protect private keys with strong passwords
- ✅ Store keys in hardware security modules (HSM) when possible

### Digital Signatures
- ✅ Use SHA-256 or stronger hash algorithms
- ✅ Verify signatures using trusted certificates
- ✅ Implement proper certificate validation
- ✅ Check certificate expiration and revocation

### Key Management
- ✅ Use PKCS#12 format for keystore files
- ✅ Use strong passwords for keystores (minimum 12 characters)
- ✅ Implement proper key rotation policies
- ✅ Never hardcode passwords or keys in source code
- ✅ Use environment variables or secure vaults for sensitive data
- ✅ Regularly backup keystores securely
- ✅ Implement key destruction procedures

### Certificate Management
- ✅ Use appropriate validity periods (not too long)
- ✅ Implement certificate revocation checking (CRL/OCSP)
- ✅ Validate entire certificate chains
- ✅ Check certificate purposes (Key Usage, Extended Key Usage)
- ✅ Maintain trusted root CA certificates
- ✅ Monitor certificate expiration dates

### Common Pitfalls to Avoid
- ❌ Using weak algorithms (DES, 3DES, RC4)
- ❌ Using small key sizes
- ❌ Reusing IVs or nonces
- ❌ Implementing custom cryptography
- ❌ Ignoring certificate validation errors
- ❌ Storing passwords or keys in plaintext
- ❌ Using timing-unsafe comparison functions
- ❌ Trusting all certificates in production

### Performance Considerations
- Cache `SecureRandom`, `MessageDigest`, and `Cipher` instances when possible
- Use `ThreadLocal` for thread-safe instance reuse
- Consider connection pooling for cryptographic operations
- Profile before optimizing cryptographic code

## Security Warnings

⚠️ **Educational Purpose Only**: These examples are for learning purposes and may not include all production-ready security measures.

⚠️ **Key Storage**: The examples use hardcoded passwords (`"changeit"`) for demonstration. In production:
- Use environment variables or secure configuration management
- Use hardware security modules (HSM) or key management services (KMS)
- Implement proper access controls

⚠️ **Certificate Validation**: Production systems must:
- Validate certificate chains completely
- Check certificate revocation status (CRL/OCSP)
- Verify certificate purposes and constraints
- Use trusted root CA certificates

⚠️ **Key Distribution**: The examples include keys for demonstration. In production:
- Never include private keys in source control
- Never transmit encryption keys alongside encrypted data
- Use secure key exchange protocols (TLS, Diffie-Hellman)

## Contributing

This is a training repository. Feel free to:
- Report issues
- Suggest improvements
- Add more examples
- Improve documentation

## License

This training material is provided for educational purposes.

## Acknowledgments

- Oracle Java Security Team
- Bouncy Castle Contributors
- Security research community

---

**Last Updated:** December 3, 2025

**Java Version:** 21.0.4

**Bouncy Castle Version:** 1.82

