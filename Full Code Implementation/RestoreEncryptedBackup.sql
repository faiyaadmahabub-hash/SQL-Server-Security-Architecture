/*
SmartBankDB - prepare the destination instance for an encrypted restore

STEP 1: WINDOWS FILE PERMISSIONS
Already completed on your RESTORETEST instance. Only repeat if needed.
Run the following commands in Command Prompt as Administrator, NOT in SSMS.
These are the certificate names and export paths from SmartBankDB_Codebase.sql.

 takeown /F "C:\SQLKeys\TDE_SmartBankDB_Cert.cer" /A
 takeown /F "C:\SQLKeys\TDE_SmartBankDB_Cert.pvk" /A
 takeown /F "C:\SQLKeys\BackupEncryptCert.cer" /A
 takeown /F "C:\SQLKeys\BackupEncryptCert.pvk" /A
 icacls "C:\SQLKeys" /grant "NT SERVICE\MSSQL$RESTORETEST:RX"
 icacls "C:\SQLKeys\TDE_SmartBankDB_Cert.cer" /grant "*S-1-5-32-544:F" "NT SERVICE\MSSQL$RESTORETEST:R"
 icacls "C:\SQLKeys\TDE_SmartBankDB_Cert.pvk" /grant "*S-1-5-32-544:F" "NT SERVICE\MSSQL$RESTORETEST:R"
 icacls "C:\SQLKeys\BackupEncryptCert.cer" /grant "*S-1-5-32-544:F" "NT SERVICE\MSSQL$RESTORETEST:R"
 icacls "C:\SQLKeys\BackupEncryptCert.pvk" /grant "*S-1-5-32-544:F" "NT SERVICE\MSSQL$RESTORETEST:R"

The service also needs Read access to the selected .bak file.
On another instance, substitute its actual SQL Server service account.

STEP 2: IMPORT CERTIFICATES
Connect SSMS to FAIYAAD\RESTORETEST as sysadmin, then execute the SQL below.
Passwords are from the uploaded codebase; substitute actual passwords if changed.
Existing master key and certificates are preserved.
*/
USE master;
GO

IF NOT EXISTS (
    SELECT 1 FROM sys.symmetric_keys
    WHERE name = '##MS_DatabaseMasterKey##'
)
BEGIN
    CREATE MASTER KEY
    ENCRYPTION BY PASSWORD = 'SmartBank_MasterDMK_P@ss2026!';
END;
GO

IF NOT EXISTS (
    SELECT 1 FROM sys.certificates
    WHERE name = 'TDE_SmartBankDB_Cert'
)
BEGIN
    CREATE CERTIFICATE TDE_SmartBankDB_Cert
    FROM FILE = 'C:\SQLKeys\TDE_SmartBankDB_Cert.cer'
    WITH PRIVATE KEY (
        FILE = 'C:\SQLKeys\TDE_SmartBankDB_Cert.pvk',
        DECRYPTION BY PASSWORD = 'SmartBank_KeyBackup_P@ss2026!'
    );
END;
GO

IF NOT EXISTS (
    SELECT 1 FROM sys.certificates
    WHERE name = 'BackupEncryptCert'
)
BEGIN
    CREATE CERTIFICATE BackupEncryptCert
    FROM FILE = 'C:\SQLKeys\BackupEncryptCert.cer'
    WITH PRIVATE KEY (
        FILE = 'C:\SQLKeys\BackupEncryptCert.pvk',
        DECRYPTION BY PASSWORD = 'SmartBank_KeyBackup_P@ss2026!'
    );
END;
GO

SELECT name, pvt_key_encryption_type_desc AS PrivateKeyProtection
FROM sys.certificates
WHERE name IN ('TDE_SmartBankDB_Cert', 'BackupEncryptCert');
GO
-- Continue only if both certificates have private keys and no errors occurred.
-- For your setup, both should show ENCRYPTED_BY_MASTER_KEY.

/*
STEP 3: RESTORE USING SSMS (MANUAL)
1. On FAIYAAD\RESTORETEST, right-click Databases > Restore Database.
2. Device > Add > select your full .bak file:
   C:\SQLBackups\Full\SmartBankDB_Full_20260909_120001.bak
3. Destination database: SmartBankDB_RestoreProof (must not already exist;
   choose another new name if keeping an existing restored copy).
4. Files > Relocate all files to folder. Both FOLDER boxes:
   C:\Program Files\Microsoft SQL Server\MSSQL16.RESTORETEST\MSSQL\DATA
5. In the table's Restore As cells, use these FULL FILE paths:
   C:\Program Files\Microsoft SQL Server\MSSQL16.RESTORETEST\MSSQL\DATA\SmartBankDB_RestoreProof.mdf
   C:\Program Files\Microsoft SQL Server\MSSQL16.RESTORETEST\MSSQL\DATA\SmartBankDB_RestoreProof_log.ldf
   If choosing another database name, use matching unique filenames.
6. Options: RESTORE WITH RECOVERY; leave WITH REPLACE unchecked.
7. Click OK. Save the successful restore message for your demonstration.

AFTER RESTORE: IC-NUMBER ACCESS
The restore wizard completes the database restore. Your codebase ALSO encrypts
customer IC numbers separately. Run the following block separately AFTER restore
if you need to demonstrate their decryption. It is commented out so running this
preparation file does not try to access a database that has not been restored yet.
Use your restored database name if different.

USE SmartBankDB_RestoreProof;
GO
OPEN MASTER KEY DECRYPTION BY PASSWORD = 'SmartBank_DMK_P@ss2026!';
IF NOT EXISTS (
    SELECT 1 FROM sys.databases
    WHERE database_id = DB_ID() AND is_master_key_encrypted_by_server = 1
)
    ALTER MASTER KEY ADD ENCRYPTION BY SERVICE MASTER KEY;
CLOSE MASTER KEY;
GO

The certificates in master do not need reimporting for each repeat restore.
Actual restore success and data access must be demonstrated on your SQL instance.
*/
