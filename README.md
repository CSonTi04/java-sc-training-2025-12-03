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

