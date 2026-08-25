@echo off
"C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe" sign /sha1 59466471DEA1A50A10B5BD548F226921A4D940AF /fd sha256 /tr http://time.certum.pl /td sha256 /d "1id.com HSM Identity Enrollment Helper" /du "https://1id.com" "C:\Users\cnd\Downloads\cursor\1id\websites\1id.com\sdk\oneid-enroll\build\oneid-enroll-windows-amd64.exe"
echo EXIT_CODE=%ERRORLEVEL%
