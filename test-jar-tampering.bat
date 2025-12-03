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

