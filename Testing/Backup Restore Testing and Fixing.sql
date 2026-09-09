USE master;
GO

CREATE CERTIFICATE TDE_SmartBankDB_Cert
FROM FILE = 'C:\SQLKeys\TDE_SmartBankDB_Cert.cer'
WITH PRIVATE KEY (
    FILE = 'C:\SQLKeys\TDE_SmartBankDB_Cert.pvk',
    DECRYPTION BY PASSWORD = 'SmartBank_KeyBackup_P@ss2026!'
);
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

SELECT
    name,
    pvt_key_encryption_type_desc AS PrivateKeyProtection
FROM sys.certificates
WHERE name IN (
    'TDE_SmartBankDB_Cert',
    'BackupEncryptCert'
);