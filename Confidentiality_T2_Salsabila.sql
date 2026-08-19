-- SALSABILA (TP078641) CONFIDENTIALITY TC2 // ENCRYPTION  
/* ================================================================
   Task C2: Encrypt the whole database (TDE) + encrypt Customer.ICNumber
   specifically (CLE), and back up every key/certificate involved.

   Report reference : Section 3.3 (Encryption), Table 2
   Weakness addressed: Weakness 5 (plaintext data / unprotected
   backups), Weakness 22 (no encryption key/certificate backup)

   BEFORE RUNNING:
   Create a folder for key/certificate backups, e.g. C:\SQLKeys\,
   and grant your SQL Server service account Modify permission on
   it — same steps you already did for C:\SQLAudit\ in task C6
   (Properties > Security > Edit > Add > your service account >
   Modify). This is required or BACKUP CERTIFICATE / BACKUP MASTER
   KEY will fail with an invalid path error, exactly like C6 did.

   Passwords below are placeholders for this assignment. In a real
   deployment these must be unique per key, generated securely, and
   stored somewhere separate from both the database and its backups
   (e.g. a password manager / vault) — never in a script like this.
   ================================================================ */


-- IMPLEMENTATION >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

USE SmartBankDB;
GO

/* ================================================================
   [C2.1] DATABASE MASTER KEY (SmartBankDB)
   Root of this database's own encryption hierarchy. Protects the
   CLE certificate created in [C2.2].
   ================================================================ */
IF NOT EXISTS (SELECT 1 FROM sys.symmetric_keys WHERE name = '##MS_DatabaseMasterKey##')
    CREATE MASTER KEY ENCRYPTION BY PASSWORD = 'SmartBank_DMK_P@ss2026!';
GO
/* ================================================================
   [C2.2] CLE CERTIFICATE
   Protected automatically by the DMK created above (no password
   needed for creation — DMK handles it).
   ================================================================ */
IF NOT EXISTS (SELECT 1 FROM sys.certificates WHERE name = 'CLE_ICNumber_Cert')
    CREATE CERTIFICATE CLE_ICNumber_Cert
        WITH SUBJECT = 'Column-level encryption certificate for Customer.ICNumber';
GO
/* ================================================================
   [C2.3] CLE SYMMETRIC KEY
   The actual key that performs encryption/decryption of ICNumber
   values. AES_256 is a strong, modern, widely-approved algorithm.
   Protected by the certificate above.
   ================================================================ */
IF NOT EXISTS (SELECT 1 FROM sys.symmetric_keys WHERE name = 'CLE_ICNumber_SymKey')
    CREATE SYMMETRIC KEY CLE_ICNumber_SymKey
        WITH ALGORITHM = AES_256
        ENCRYPTION BY CERTIFICATE CLE_ICNumber_Cert;
GO

/* ================================================================
   [C2.4] MIGRATE EXISTING ICNumber DATA
   The baseline seed script encrypted ICNumber with a TEMPORARY
   placeholder (ENCRYPTBYPASSPHRASE('TEMP_PLACEHOLDER_KEY', ...)),
   flagged explicitly in that script as needing real encryption.
   This decrypts using the old placeholder method and re-encrypts
   using the real symmetric key, in one UPDATE.
   ================================================================ */

OPEN SYMMETRIC KEY CLE_ICNumber_SymKey
    DECRYPTION BY CERTIFICATE CLE_ICNumber_Cert;
 
UPDATE dbo.Customer
SET ICNumber = EncryptByKey(
    Key_GUID('CLE_ICNumber_SymKey'),
    CONVERT(VARBINARY(MAX), CONVERT(NVARCHAR(20), DecryptByPassphrase('TEMP_PLACEHOLDER_KEY', ICNumber)))
);
 
CLOSE SYMMETRIC KEY CLE_ICNumber_SymKey;
GO
 
PRINT 'C2.4 — ICNumber data migrated from placeholder to real CLE encryption.';
GO

/* ================================================================
   [C2.5] DECRYPT WRAPPER PROCEDURE
   Gives authorized staff a controlled way to view a customer's
   real IC number, without granting anyone direct key access.
 
   Uses WITH EXECUTE AS OWNER: by default, a procedure runs under
   the CALLER's own security context, so a caller with only EXECUTE
   permission on this procedure would still be personally checked
   for permission to open the symmetric key/certificate directly —
   and fail. WITH EXECUTE AS OWNER makes the entire procedure body
   run under the OWNER's (dbo's) identity instead, regardless of
   who calls it. Callers still only ever need plain EXECUTE on the
   procedure — no separate permission on the certificate or key is
   ever granted to them.
 
   Access matches Table 5's vw_CustomerAll pattern: Bank_Manager
   and Bank_Officer only. NOT granted to DBA — Section 3.1 is
   explicit that the DBA role has no access to operational
   business data beyond their own staff record. NOT granted to
   Customer either — Section 3.1 states customers do not have
   direct access to their own Customer table row at all.
   ================================================================ */

CREATE OR ALTER PROCEDURE dbo.sp_DecryptICNumber
    @CustomerID INT
WITH EXECUTE AS OWNER
AS
BEGIN
    SET NOCOUNT ON;
 
    OPEN SYMMETRIC KEY CLE_ICNumber_SymKey
        DECRYPTION BY CERTIFICATE CLE_ICNumber_Cert;
 
    SELECT
        CustomerID,
        CustomerName,
        CONVERT(NVARCHAR(20), DecryptByKey(ICNumber)) AS ICNumber_Decrypted
    FROM dbo.Customer
    WHERE CustomerID = @CustomerID;
 
    CLOSE SYMMETRIC KEY CLE_ICNumber_SymKey;
END;
GO
 
GRANT EXECUTE ON dbo.sp_DecryptICNumber TO Bank_Manager;
GO
GRANT EXECUTE ON dbo.sp_DecryptICNumber TO Bank_Officer;
GO


/* ================================================================
   [C2.6] MASTER-LEVEL DATABASE MASTER KEY
   TDE's certificate must live in the master system database
   (it's a server-scoped feature), which requires its own DMK.
   ================================================================ */
USE master;
GO

IF NOT EXISTS (SELECT 1 FROM sys.symmetric_keys WHERE name = '##MS_DatabaseMasterKey##')
    CREATE MASTER KEY ENCRYPTION BY PASSWORD = 'SmartBank_MasterDMK_P@ss2026!';
GO

/* ================================================================
   [C2.7] TDE CERTIFICATE (server-level, stored in master)
   ================================================================ */
IF NOT EXISTS (SELECT 1 FROM sys.certificates WHERE name = 'TDE_SmartBankDB_Cert')
    CREATE CERTIFICATE TDE_SmartBankDB_Cert
        WITH SUBJECT = 'TDE certificate for SmartBankDB';
GO

/* ================================================================
   [C2.8] DATABASE ENCRYPTION KEY (SmartBankDB)
   The key TDE actually uses to encrypt the database file,
   protected by the TDE certificate above.
   ================================================================ */
USE SmartBankDB;
GO

IF NOT EXISTS (SELECT 1 FROM sys.dm_database_encryption_keys WHERE database_id = DB_ID('SmartBankDB'))
BEGIN
    CREATE DATABASE ENCRYPTION KEY
        WITH ALGORITHM = AES_256
        ENCRYPTION BY SERVER CERTIFICATE TDE_SmartBankDB_Cert;
END
GO

/* ================================================================
   [C2.9] ENABLE TDE
   Switches on whole-database file encryption. Run from master.
   ================================================================ */
USE master;
GO

ALTER DATABASE SmartBankDB SET ENCRYPTION ON;
GO

-- Check progress/status (encryption_state 3 = Encrypted, complete)
SELECT
    db.name AS database_name,
    dek.encryption_state,
    dek.percent_complete
FROM sys.dm_database_encryption_keys dek
JOIN sys.databases db ON dek.database_id = db.database_id
WHERE db.name = 'SmartBankDB';
GO

/* ================================================================
   [C2.10] BACKUP: SmartBankDB's Database Master Key
   ================================================================ */
USE SmartBankDB;
GO

BACKUP MASTER KEY TO FILE = 'C:\SQLKeys\SmartBankDB_DMK.key'
    ENCRYPTION BY PASSWORD = 'SmartBank_KeyBackup_P@ss2026!';
GO

/* ================================================================
   [C2.11] BACKUP: CLE Certificate + private key
   WITH PRIVATE KEY is essential — without it, only the public
   portion is saved, which is NOT enough to ever decrypt data again.
   ================================================================ */
BACKUP CERTIFICATE CLE_ICNumber_Cert
    TO FILE = 'C:\SQLKeys\CLE_ICNumber_Cert.cer'
    WITH PRIVATE KEY (
        FILE = 'C:\SQLKeys\CLE_ICNumber_Cert.pvk',
        ENCRYPTION BY PASSWORD = 'SmartBank_KeyBackup_P@ss2026!'
    );
GO

/* ================================================================
   [C2.12] BACKUP: TDE Certificate + private key (from master)
   ================================================================ */
USE master;
GO

BACKUP CERTIFICATE TDE_SmartBankDB_Cert
    TO FILE = 'C:\SQLKeys\TDE_SmartBankDB_Cert.cer'
    WITH PRIVATE KEY (
        FILE = 'C:\SQLKeys\TDE_SmartBankDB_Cert.pvk',
        ENCRYPTION BY PASSWORD = 'SmartBank_KeyBackup_P@ss2026!'
    );
GO

USE SmartBankDB;
GO

PRINT 'C2 — TDE and CLE setup complete. All keys and certificates backed up.';

-- TEST CASE >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

USE SmartBankDB;
GO

/* ================================================================
   ONE-TIME SETUP — dedicated test users for Bank_Manager,
   Bank_Officer, Customer, plus reuse of test_dba_user from C6.
   ================================================================ */
USE master;
GO

IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name = 'test_manager_login')
    CREATE LOGIN test_manager_login WITH PASSWORD = 'Str0ngTestPass!123';
GO
IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name = 'test_officer_login')
    CREATE LOGIN test_officer_login WITH PASSWORD = 'Str0ngTestPass!123';
GO
IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name = 'test_customer_login')
    CREATE LOGIN test_customer_login WITH PASSWORD = 'Str0ngTestPass!123';
GO

USE SmartBankDB;
GO

IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = 'test_manager_user')
    CREATE USER test_manager_user FOR LOGIN test_manager_login;
GO
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = 'test_officer_user')
    CREATE USER test_officer_user FOR LOGIN test_officer_login;
GO
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = 'test_customer_user')
    CREATE USER test_customer_user FOR LOGIN test_customer_login;
GO

IF NOT EXISTS (SELECT 1 FROM sys.database_role_members drm
                JOIN sys.database_principals r ON drm.role_principal_id = r.principal_id
                JOIN sys.database_principals m ON drm.member_principal_id = m.principal_id
                WHERE r.name = 'Bank_Manager' AND m.name = 'test_manager_user')
    ALTER ROLE Bank_Manager ADD MEMBER test_manager_user;
GO
IF NOT EXISTS (SELECT 1 FROM sys.database_role_members drm
                JOIN sys.database_principals r ON drm.role_principal_id = r.principal_id
                JOIN sys.database_principals m ON drm.member_principal_id = m.principal_id
                WHERE r.name = 'Bank_Officer' AND m.name = 'test_officer_user')
    ALTER ROLE Bank_Officer ADD MEMBER test_officer_user;
GO
IF NOT EXISTS (SELECT 1 FROM sys.database_role_members drm
                JOIN sys.database_principals r ON drm.role_principal_id = r.principal_id
                JOIN sys.database_principals m ON drm.member_principal_id = m.principal_id
                WHERE r.name = 'Customer' AND m.name = 'test_customer_user')
    ALTER ROLE Customer ADD MEMBER test_customer_user;
GO


/* ================================================================ 
   T-C2.1 — POSITIVE: TDE is fully enabled
   ================================================================ */
PRINT '--- T-C2.1: checking TDE encryption state ---';

SELECT
    db.name AS database_name,
    dek.encryption_state,     -- expect 3 = Encrypted
    dek.percent_complete      -- expect 0 once fully done
FROM sys.dm_database_encryption_keys dek
JOIN sys.databases db ON dek.database_id = db.database_id
WHERE db.name = 'SmartBankDB';
GO


/* ================================================================ PASSED
   T-C2.2 — POSITIVE: raw ICNumber column is unreadable ciphertext
   (proves CLE is actually protecting the column, not just present)
   ================================================================ */
PRINT '--- T-C2.2: viewing raw (encrypted) ICNumber values ---';

SELECT TOP 5 CustomerID, CustomerName, ICNumber, ICNumberHash
FROM dbo.Customer;
-- Expected: ICNumber column shows unreadable binary/hex data,
-- NOT a readable IC number string
GO

 
/* ================================================================
   T-C2.3 — POSITIVE: Bank_Manager can decrypt via the wrapper
   ================================================================ */
PRINT '--- T-C2.3: Bank_Manager decrypting ICNumber ---';
 
EXECUTE AS USER = 'test_manager_user';
EXEC dbo.sp_DecryptICNumber @CustomerID = 1;
-- Expected: succeeds, ICNumber_Decrypted shows a readable IC number
REVERT;
GO

/* ================================================================
   T-C2.4 — POSITIVE: Bank_Officer can decrypt via the wrapper
   ================================================================ */
PRINT '--- T-C2.4: Bank_Officer decrypting ICNumber ---';

EXECUTE AS USER = 'test_officer_user';
EXEC dbo.sp_DecryptICNumber @CustomerID = 1;
-- Expected: succeeds, same readable IC number as T-C2.3
REVERT;
GO

/* ================================================================
   T-C2.5 — NEGATIVE: DBA is blocked from decrypting
   (Section 3.1: DBA has no access to operational business data)
   ================================================================ */
PRINT '--- T-C2.5: DBA attempting to decrypt ICNumber (should fail) ---';

EXECUTE AS USER = 'test_dba_user';   -- reused from C6
EXEC dbo.sp_DecryptICNumber @CustomerID = 1;
-- Expected: Msg 229 EXECUTE permission denied
REVERT;
GO

/* ================================================================
   T-C2.6 — NEGATIVE: Customer is blocked from decrypting
   (Section 3.1: customers have no direct access to their own
   Customer table row at all)
   ================================================================ */
PRINT '--- T-C2.6: Customer attempting to decrypt ICNumber (should fail) ---';

EXECUTE AS USER = 'test_customer_user';
EXEC dbo.sp_DecryptICNumber @CustomerID = 1;
-- Expected: Msg 229 EXECUTE permission denied
REVERT;
GO

/* ================================================================
   T-C2.7 — NEGATIVE: no one can open the symmetric key directly
   without going through the wrapper (proves no bypass route)
   ================================================================ */
PRINT '--- T-C2.7: Bank_Officer attempting to bypass the wrapper directly ---';

EXECUTE AS USER = 'test_officer_user';
OPEN SYMMETRIC KEY CLE_ICNumber_SymKey DECRYPTION BY CERTIFICATE CLE_ICNumber_Cert;
-- Expected: permission error — test_officer_user has no direct
-- CONTROL permission on the certificate, only EXECUTE on the
-- wrapper procedure (which works via ownership chaining instead)
REVERT;
GO

/* ================================================================
   T-C2.8 — POSITIVE: decrypted value round-trips correctly
   (confirms encryption didn't corrupt the underlying data)
   ================================================================ */
PRINT '--- T-C2.8: confirming decrypted IC number matches its hash ---';
 
OPEN SYMMETRIC KEY CLE_ICNumber_SymKey DECRYPTION BY CERTIFICATE CLE_ICNumber_Cert;
 
SELECT TOP 5
    CustomerID,
    CONVERT(NVARCHAR(20), DecryptByKey(ICNumber)) AS Decrypted_ICNumber,
    ICNumberHash,
    HASHBYTES('SHA2_256', CONVERT(NVARCHAR(20), DecryptByKey(ICNumber))) AS Recomputed_Hash
FROM dbo.Customer;
-- Expected: ICNumberHash and Recomputed_Hash match exactly for
-- every row, proving the migrated data is correct, not corrupted
 
CLOSE SYMMETRIC KEY CLE_ICNumber_SymKey;
GO


/* ================================================================
   T-C2.9 — POSITIVE: key/certificate backup files exist
   (cannot be checked via T-SQL directly — manual verification)
   ================================================================ */
PRINT '--- T-C2.9: MANUAL STEP — verify backup files exist ---';
PRINT 'Check C:\SQLKeys\ contains: SmartBankDB_DMK.key, CLE_ICNumber_Cert.cer, CLE_ICNumber_Cert.pvk, TDE_SmartBankDB_Cert.cer, TDE_SmartBankDB_Cert.pvk';
GO

/* ================================================================
   CLEANUP — remove test artifacts (keeps test_dba_user from C6)
   ================================================================ */
PRINT '--- Cleaning up C2 test users ---';
 
IF EXISTS (SELECT 1 FROM sys.database_principals WHERE name = 'test_manager_user')
    DROP USER test_manager_user;
IF EXISTS (SELECT 1 FROM sys.database_principals WHERE name = 'test_officer_user')
    DROP USER test_officer_user;
IF EXISTS (SELECT 1 FROM sys.database_principals WHERE name = 'test_customer_user')
    DROP USER test_customer_user;
GO
 
USE master;
GO
IF EXISTS (SELECT 1 FROM sys.server_principals WHERE name = 'test_manager_login')
    DROP LOGIN test_manager_login;
IF EXISTS (SELECT 1 FROM sys.server_principals WHERE name = 'test_officer_login')
    DROP LOGIN test_officer_login;
IF EXISTS (SELECT 1 FROM sys.server_principals WHERE name = 'test_customer_login')
    DROP LOGIN test_customer_login;
GO
 
USE SmartBankDB;
GO
 
PRINT 'C2 test suite complete.';
 