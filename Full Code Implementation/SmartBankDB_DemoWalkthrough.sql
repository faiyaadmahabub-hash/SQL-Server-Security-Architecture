-- ====================================================================
-- SmartBankDB -- DEMO WALKTHROUGH SCRIPT
-- ====================================================================
-- This is NOT the exhaustive test suite (that's FeatureTests.sql).
-- This file is curated and narrated specifically around the
-- lecturer's 9-point demo checklist, in order, with Point 9 moved
-- to sit right after Point 1's customer login (it flows naturally
-- there -- still clearly labeled "POINT 9" so it's obvious which
-- checklist item it covers).
--
-- Every block below is separated by GO -- run one block at a time,
-- reading the comment above it aloud first. GO isn't optional
-- styling here: several blocks reuse the same variable names
-- (@Success, @Message, etc.), so without GO separating them as
-- independent batches, the script would fail to compile at all if
-- ever run start to finish.
--
-- This file is self-contained: it does NOT assume FeatureTests.sql
-- has been run first. It creates its own demo login/user
-- principals and sets known passwords on the 4 demo personas, so
-- it works straight after SmartBankDB_Codebase.sql alone.
--
-- Demo personas used throughout (all real seeded accounts):
--   DBA:      staff_aisharahman   (StaffID 1)
--   Manager:  staff_faridosman    (StaffID 2)
--   Officer:  staff_hafizzainal   (StaffID 7)
--   Customer: cust_aimanhaziq     (CustomerID 2, owns AccountID 2/3/23)
-- All demo passwords: Test1234!
--
-- IMPORTANT -- SESSION_CONTEXT caveat, applies throughout this file:
-- SESSION_CONTEXT persists for the whole SSMS session, not just
-- within one EXECUTE AS/REVERT block. If a block behaves
-- unexpectedly because of a PREVIOUS login still being "remembered,"
-- open a brand new query window and re-run sp_Login for that block.
-- ====================================================================

USE master;
GO

IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name = 'demo_dba_login')
    CREATE LOGIN demo_dba_login WITH PASSWORD = 'Str0ngDemoPass!123';
GO
IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name = 'demo_manager_login')
    CREATE LOGIN demo_manager_login WITH PASSWORD = 'Str0ngDemoPass!123';
GO
IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name = 'demo_officer_login')
    CREATE LOGIN demo_officer_login WITH PASSWORD = 'Str0ngDemoPass!123';
GO
IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name = 'demo_customer_login')
    CREATE LOGIN demo_customer_login WITH PASSWORD = 'Str0ngDemoPass!123';
GO

USE SmartBankDB;
GO

IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = 'demo_dba_user')
    CREATE USER demo_dba_user FOR LOGIN demo_dba_login;
GO
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = 'demo_manager_user')
    CREATE USER demo_manager_user FOR LOGIN demo_manager_login;
GO
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = 'demo_officer_user')
    CREATE USER demo_officer_user FOR LOGIN demo_officer_login;
GO
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = 'demo_customer_user')
    CREATE USER demo_customer_user FOR LOGIN demo_customer_login;
GO

IF NOT EXISTS (SELECT 1 FROM sys.database_role_members drm
                JOIN sys.database_principals r ON drm.role_principal_id = r.principal_id
                JOIN sys.database_principals m ON drm.member_principal_id = m.principal_id
                WHERE r.name = 'DBA' AND m.name = 'demo_dba_user')
    ALTER ROLE DBA ADD MEMBER demo_dba_user;
GO
IF NOT EXISTS (SELECT 1 FROM sys.database_role_members drm
                JOIN sys.database_principals r ON drm.role_principal_id = r.principal_id
                JOIN sys.database_principals m ON drm.member_principal_id = m.principal_id
                WHERE r.name = 'Bank_Manager' AND m.name = 'demo_manager_user')
    ALTER ROLE Bank_Manager ADD MEMBER demo_manager_user;
GO
IF NOT EXISTS (SELECT 1 FROM sys.database_role_members drm
                JOIN sys.database_principals r ON drm.role_principal_id = r.principal_id
                JOIN sys.database_principals m ON drm.member_principal_id = m.principal_id
                WHERE r.name = 'Bank_Officer' AND m.name = 'demo_officer_user')
    ALTER ROLE Bank_Officer ADD MEMBER demo_officer_user;
GO
IF NOT EXISTS (SELECT 1 FROM sys.database_role_members drm
                JOIN sys.database_principals r ON drm.role_principal_id = r.principal_id
                JOIN sys.database_principals m ON drm.member_principal_id = m.principal_id
                WHERE r.name = 'Customer' AND m.name = 'demo_customer_user')
    ALTER ROLE Customer ADD MEMBER demo_customer_user;
GO

-- Set known passwords on the 4 real seeded demo personas
DECLARE @S1 VARBINARY(32) = CRYPT_GEN_RANDOM(32);
UPDATE dbo.UserLogin SET Salt = @S1, PasswordHash = HASHBYTES('SHA2_512', @S1 + CONVERT(VARBINARY(4000), N'Test1234!')),
    PasswordLastChanged = SYSDATETIME(), FailedLoginAttempts = 0, LockoutUntil = NULL
WHERE Username = 'staff_aisharahman';
GO

DECLARE @S2 VARBINARY(32) = CRYPT_GEN_RANDOM(32);
UPDATE dbo.UserLogin SET Salt = @S2, PasswordHash = HASHBYTES('SHA2_512', @S2 + CONVERT(VARBINARY(4000), N'Test1234!')),
    PasswordLastChanged = SYSDATETIME(), FailedLoginAttempts = 0, LockoutUntil = NULL
WHERE Username = 'staff_faridosman';
GO

DECLARE @S3 VARBINARY(32) = CRYPT_GEN_RANDOM(32);
UPDATE dbo.UserLogin SET Salt = @S3, PasswordHash = HASHBYTES('SHA2_512', @S3 + CONVERT(VARBINARY(4000), N'Test1234!')),
    PasswordLastChanged = SYSDATETIME(), FailedLoginAttempts = 0, LockoutUntil = NULL
WHERE Username = 'staff_hafizzainal';
GO

DECLARE @S4 VARBINARY(32) = CRYPT_GEN_RANDOM(32);
UPDATE dbo.UserLogin SET Salt = @S4, PasswordHash = HASHBYTES('SHA2_512', @S4 + CONVERT(VARBINARY(4000), N'Test1234!')),
    PasswordLastChanged = SYSDATETIME(), FailedLoginAttempts = 0, LockoutUntil = NULL
WHERE Username = 'cust_aimanhaziq';
GO

PRINT 'Demo environment ready. Begin walkthrough below.';
GO


-- ====================================================================
-- POINT 1 -- "Login as few different users"
-- ====================================================================

-- 1a. Login as DBA
EXECUTE AS USER = 'demo_dba_user';
DECLARE @Success BIT, @Expired BIT, @Message NVARCHAR(200);
EXEC sp_Login 'staff_aisharahman', 'Test1234!', @Success OUTPUT, @Expired OUTPUT, @Message OUTPUT;
SELECT @Success AS Success, @Message AS Message;
SELECT SESSION_CONTEXT(N'UserType') AS UserType, SESSION_CONTEXT(N'StaffID') AS StaffID;
REVERT;
GO
-- Expected: Success = 1, UserType = 'Staff', StaffID = 1

-- 1b. Login as Bank Manager
EXECUTE AS USER = 'demo_manager_user';
DECLARE @Success BIT, @Expired BIT, @Message NVARCHAR(200);
EXEC sp_Login 'staff_faridosman', 'Test1234!', @Success OUTPUT, @Expired OUTPUT, @Message OUTPUT;
SELECT @Success AS Success, @Message AS Message;
SELECT SESSION_CONTEXT(N'UserType') AS UserType, SESSION_CONTEXT(N'StaffID') AS StaffID;
REVERT;
GO
-- Expected: Success = 1, StaffID = 2

-- 1c. Login as Bank Officer
EXECUTE AS USER = 'demo_officer_user';
DECLARE @Success BIT, @Expired BIT, @Message NVARCHAR(200);
EXEC sp_Login 'staff_hafizzainal', 'Test1234!', @Success OUTPUT, @Expired OUTPUT, @Message OUTPUT;
SELECT @Success AS Success, @Message AS Message;
SELECT SESSION_CONTEXT(N'UserType') AS UserType, SESSION_CONTEXT(N'StaffID') AS StaffID;
REVERT;
GO
-- Expected: Success = 1, StaffID = 7

-- 1d. Login as Customer
EXECUTE AS USER = 'demo_customer_user';
DECLARE @Success BIT, @Expired BIT, @Message NVARCHAR(200);
EXEC sp_Login 'cust_aimanhaziq', 'Test1234!', @Success OUTPUT, @Expired OUTPUT, @Message OUTPUT;
SELECT @Success AS Success, @Message AS Message;
SELECT SESSION_CONTEXT(N'UserType') AS UserType, SESSION_CONTEXT(N'CustomerID') AS CustomerID;
REVERT;
GO
-- Expected: Success = 1, UserType = 'Customer', CustomerID = 2


-- ====================================================================
-- POINT 9 -- "Encrypted data should be decrypted automatically for
-- the right user, per Section 1 Confidentiality"
-- (Placed here, right after the customer login, since it flows
-- naturally from 1d -- still Point 9 on the checklist.)
-- ====================================================================

-- 9a. Customer sees their OWN IC number, decrypted automatically
EXECUTE AS USER = 'demo_customer_user';
DECLARE @Success BIT, @Expired BIT, @Message NVARCHAR(200);
EXEC sp_Login 'cust_aimanhaziq', 'Test1234!', @Success OUTPUT, @Expired OUTPUT, @Message OUTPUT;
EXEC dbo.sp_DecryptOwnICNumber;
REVERT;
GO
-- Expected: one row, ICNumber_Decrypted shows Aiman's real 12-digit
-- IC number -- decrypted automatically, no manual key handling by
-- the user

-- 9b. Same customer CANNOT read the raw Customer table directly --
-- proves decryption is a controlled, narrow exception, not a
-- general data-access opening
EXECUTE AS USER = 'demo_customer_user';
SELECT * FROM dbo.Customer;
REVERT;
GO
-- Expected: "The SELECT permission was denied..." error


-- ====================================================================
-- POINT 2 -- "Show me the users and the permission settings for
-- each role"
-- ====================================================================

-- 2a. The 5 roles in the system (4 the assignment names + RecoveryAdmin)
SELECT name AS RoleName, type_desc
FROM sys.database_principals
WHERE type = 'R' AND name NOT LIKE 'db_%'
ORDER BY name;
GO

-- 2b. Who's a member of each role -- including the RecoveryAdmin/DBA
-- nesting specifically worth pointing at
SELECT r.name AS RoleName, m.name AS MemberName, m.type_desc AS MemberType
FROM sys.database_role_members drm
JOIN sys.database_principals r ON drm.role_principal_id = r.principal_id
JOIN sys.database_principals m ON drm.member_principal_id = m.principal_id
WHERE r.name NOT LIKE 'db_%'
ORDER BY r.name, m.name;
GO
-- Expected: shows DBA as a MEMBER of RecoveryAdmin, alongside the
-- ordinary user->role memberships

-- 2c. What each role can actually do -- object-level permissions,
-- readable
SELECT
    dp.name AS RoleName,
    perm.permission_name,
    perm.state_desc,
    OBJECT_SCHEMA_NAME(perm.major_id) + '.' + OBJECT_NAME(perm.major_id) AS ObjectName
FROM sys.database_permissions perm
JOIN sys.database_principals dp ON perm.grantee_principal_id = dp.principal_id
WHERE dp.name IN ('DBA', 'Bank_Manager', 'Bank_Officer', 'Customer', 'RecoveryAdmin')
  AND perm.major_id > 0
ORDER BY dp.name, ObjectName;
GO


-- ====================================================================
-- POINT 3 -- "Show proof that permission settings meet the
-- assignment's requirements -- run SQL queries one by one"
-- Walking Section 1 (Confidentiality) then Section 2 (Integrity),
-- one requirement at a time, positive then negative.
-- ====================================================================

-- --- Confidentiality Req 1: all users must be authenticated ---
-- (already proven in Point 1 -- sp_Login is the only path in)

-- --- Confidentiality Req 2: all authenticated users see Staff
-- name + contact ---
EXECUTE AS USER = 'demo_customer_user';
SELECT * FROM dbo.vw_StaffDirectory;
REVERT;
GO
-- Expected: succeeds -- even a Customer sees name + phone for all staff

-- --- Confidentiality Req 3/4: Manager sees all Officers, Officer
-- does NOT ---
EXECUTE AS USER = 'demo_manager_user';
SELECT * FROM dbo.vw_AllBankOfficers;
REVERT;
GO
-- Expected: succeeds (positive -- Manager)

EXECUTE AS USER = 'demo_officer_user';
SELECT * FROM dbo.vw_AllBankOfficers;
REVERT;
GO
-- Expected: permission denied (negative -- Officer, "view only
-- their own record")

-- --- Confidentiality Req 5: DBA sees only their own record ---
EXECUTE AS USER = 'demo_dba_user';
SELECT * FROM dbo.vw_StaffOwnRecord;
REVERT;
GO
-- Expected: succeeds, exactly ONE row (Aisha Rahman, StaffID 1)

EXECUTE AS USER = 'demo_dba_user';
SELECT * FROM dbo.vw_AllBankOfficers;
REVERT;
GO
-- Expected: permission denied -- DBA has no broader staff visibility

-- --- Confidentiality Req 6: Customer sees only their OWN accounts,
-- not other customers' ---
EXECUTE AS USER = 'demo_customer_user';
DECLARE @Success BIT, @Expired BIT, @Message NVARCHAR(200);
EXEC sp_Login 'cust_aimanhaziq', 'Test1234!', @Success OUTPUT, @Expired OUTPUT, @Message OUTPUT;
SELECT * FROM dbo.vw_AccountOwn;
REVERT;
GO
-- Expected: succeeds, shows ONLY AccountID 2, 3, 23 (Aiman's own)

-- --- Integrity Req 1: only DBA creates/manages tables, not data ---
EXECUTE AS USER = 'demo_dba_user';
CREATE TABLE dbo.DemoProofTable (ID INT);
DROP TABLE dbo.DemoProofTable;
REVERT;
GO
-- Expected: succeeds (positive -- schema rights work)

EXECUTE AS USER = 'demo_dba_user';
SELECT * FROM dbo.Customer;
REVERT;
GO
-- Expected: permission denied (negative -- "not data")

EXECUTE AS USER = 'demo_dba_user';
ALTER TABLE dbo.Staff SET (SYSTEM_VERSIONING = OFF);
REVERT;
GO
-- Expected: blocked by trg_PreventVersioningDisable -- the
-- audit/recovery mechanism can't be silently disabled

-- --- Integrity Req 2: only Manager manages staff ---
EXECUTE AS USER = 'demo_manager_user';
DECLARE @Success BIT, @Expired BIT, @Message NVARCHAR(200);
EXEC sp_Login 'staff_faridosman', 'Test1234!', @Success OUTPUT, @Expired OUTPUT, @Message OUTPUT;
DECLARE @MSuccess BIT, @MMessage NVARCHAR(200);
EXEC dbo.sp_ManageStaff @StaffID = 7, @StaffName = 'Hafiz Zainal', @Position = 'Bank Officer',
    @Branch = 'Kuala Lumpur', @Phone = '0161239999', @Salary = 4700.00, @IsActive = 1,
    @Success = @MSuccess OUTPUT, @Message = @MMessage OUTPUT;
SELECT @MSuccess AS Success, @MMessage AS Message;
REVERT;
GO
-- Expected: Success = 1 (positive -- Manager updates an Officer's record)

EXECUTE AS USER = 'demo_officer_user';
DECLARE @MSuccess BIT, @MMessage NVARCHAR(200);
EXEC dbo.sp_ManageStaff @StaffID = NULL, @StaffName = 'Should Fail', @Position = 'Bank Officer',
    @Branch = 'KL', @Phone = '0100000000', @Salary = 4000.00, @IsActive = 1,
    @Success = @MSuccess OUTPUT, @Message = @MMessage OUTPUT;
REVERT;
GO
-- Expected: "EXECUTE permission was denied" (negative -- Officer
-- can't call this at all)

-- --- Integrity Req 3: only Officer manages customer accounts ---
EXECUTE AS USER = 'demo_officer_user';
DECLARE @Success BIT, @Expired BIT, @Message NVARCHAR(200);
EXEC sp_Login 'staff_hafizzainal', 'Test1234!', @Success OUTPUT, @Expired OUTPUT, @Message OUTPUT;
DECLARE @ASuccess BIT, @AMessage NVARCHAR(200);
EXEC dbo.sp_ManageAccount @AccountID = 2, @CustomerID = NULL, @AccountType = 'Savings', @IsActive = 1,
    @Success = @ASuccess OUTPUT, @Message = @AMessage OUTPUT;
SELECT @ASuccess AS Success, @AMessage AS Message;
REVERT;
GO
-- Expected: Success = 1

EXECUTE AS USER = 'demo_manager_user';
DECLARE @ASuccess BIT, @AMessage NVARCHAR(200);
EXEC dbo.sp_ManageAccount @AccountID = 2, @CustomerID = NULL, @AccountType = 'Savings', @IsActive = 1,
    @Success = @ASuccess OUTPUT, @Message = @AMessage OUTPUT;
REVERT;
GO
-- Expected: "EXECUTE permission was denied" (negative -- Manager
-- can't manage accounts, that's Officer's job)

-- --- Integrity Req 4: each staff updates own record, salary excluded ---
EXECUTE AS USER = 'demo_officer_user';
DECLARE @USuccess BIT, @UMessage NVARCHAR(200);
EXEC dbo.sp_UpdateOwnStaffRecord @Phone = '0169998888', @Success = @USuccess OUTPUT, @Message = @UMessage OUTPUT;
SELECT @USuccess AS Success, @UMessage AS Message;
REVERT;
GO
-- Expected: Success = 1 -- note sp_UpdateOwnStaffRecord has no
-- @Salary parameter at ALL, structurally proving salary can't be
-- touched through this proc, not just "denied if you try"

-- --- Integrity Req 5: only Customer performs transactions,
-- ownership enforced ---
EXECUTE AS USER = 'demo_customer_user';
DECLARE @Success BIT, @Expired BIT, @Message NVARCHAR(200);
EXEC sp_Login 'cust_aimanhaziq', 'Test1234!', @Success OUTPUT, @Expired OUTPUT, @Message OUTPUT;
DECLARE @TSuccess BIT, @TMessage NVARCHAR(200);
EXEC dbo.sp_ProcessTransaction @AccountID = 2, @TransactionType = 'Deposit', @Amount = 100.00,
    @ToAccountID = NULL, @Success = @TSuccess OUTPUT, @Message = @TMessage OUTPUT;
SELECT @TSuccess AS Success, @TMessage AS Message;
REVERT;
GO
-- Expected: Success = 1

EXECUTE AS USER = 'demo_customer_user';
DECLARE @TSuccess BIT, @TMessage NVARCHAR(200);
EXEC dbo.sp_ProcessTransaction @AccountID = 4, @TransactionType = 'Withdrawal', @Amount = 50.00,
    @ToAccountID = NULL, @Success = @TSuccess OUTPUT, @Message = @TMessage OUTPUT;
SELECT @TSuccess AS Success, @TMessage AS Message;
REVERT;
GO
-- Expected: Success = 0, "You can only perform transactions on
-- your own accounts." -- AccountID 4 belongs to Grace, not Aiman

-- --- Integrity Req 6: all manipulations, valid or invalid, are
-- logged --- (proven directly in Point 4 below, using exactly the
-- actions just performed above)


-- ====================================================================
-- POINT 4 -- "Show audit records for all the actions in Steps 1 and 3"
-- ====================================================================

-- 4a. DML audit trail -- shows the valid change AND the rejected
-- attempts from Point 3, side by side
SELECT TOP 20 LogID, TableName, ColumnName, RecordID, ChangedBy, ActionType, Activity, ChangeDate
FROM AuditSchema.AuditLog
ORDER BY LogID DESC;
GO
-- Expected: recent rows include the sp_ManageStaff phone UPDATE,
-- sp_UpdateOwnStaffRecord's phone UPDATE, the Deposit
-- TransactionRecord INSERT, AND several REJECTED rows from the
-- negative tests in Point 3 -- both valid and invalid actions
-- present, exactly matching Integrity Requirement 6

-- 4b. Specifically isolate the REJECTED rows -- the "invalid
-- actions get logged too" proof
SELECT TableName, RecordID, ChangedBy, Activity, ChangeDate
FROM AuditSchema.AuditLog
WHERE ActionType = 'REJECTED'
ORDER BY LogID DESC;
GO

-- 4c. Native SQL Server Audit -- login events, schema changes,
-- permission changes (DBA-only, via sp_DBA_ViewAuditFile)
EXECUTE AS USER = 'demo_dba_user';
EXEC dbo.sp_DBA_ViewAuditFile;
REVERT;
GO
-- Expected: shows the logins from Point 1, the CREATE/DROP TABLE
-- from Point 3's Integrity Req 1 test, and any permission changes


-- ====================================================================
-- POINT 5 -- "Show proof your scheduled backup has run correctly
-- for 3 consecutive days"
-- Pure verification -- no live action. This assumes the 3 Agent
-- Jobs have genuinely been running on the server since at least
-- 3 days before this is run.
-- ====================================================================

-- 5a. Summary counts per backup type over the last 3 days
SELECT
    type,
    CASE type WHEN 'D' THEN 'Full' WHEN 'I' THEN 'Differential' WHEN 'L' THEN 'Log' END AS BackupType,
    COUNT(*) AS RunsInLast3Days,
    MIN(backup_start_date) AS EarliestRun,
    MAX(backup_start_date) AS MostRecentRun
FROM msdb.dbo.backupset
WHERE database_name = 'SmartBankDB'
  AND backup_start_date >= DATEADD(DAY, -3, SYSDATETIME())
GROUP BY type
ORDER BY type;
GO
-- Expected: 3 rows -- roughly 12 Full (every 6h), 72 Differential
-- (hourly), 864 Log (every 5min) over a genuine 3-day window

-- 5b. Confirm no failed job runs in that window
SELECT j.name AS JobName, h.run_date, h.run_time, h.run_status,
    CASE h.run_status WHEN 0 THEN 'Failed' WHEN 1 THEN 'Succeeded' WHEN 3 THEN 'Cancelled' ELSE 'Other' END AS StatusDesc
FROM msdb.dbo.sysjobhistory h
JOIN msdb.dbo.sysjobs j ON h.job_id = j.job_id
WHERE j.name LIKE 'SmartBankDB%' AND h.run_status <> 1
ORDER BY h.run_date DESC, h.run_time DESC;
GO
-- Expected: zero rows -- no failures in the job history


-- ====================================================================
-- POINT 7 -- "Delete 1 or 2 records live, prove point-in-time
-- recovery works, efficiently and without issues"
-- Improvisational -- lecturer picks the table/record live. This is
-- a reusable 3-step TEMPLATE, shown here worked through on Staff.
-- Swap the table/proc/IDs for whatever's actually requested. Each
-- step is its own batch (GO) since @RecoveryPointTime needs to
-- survive between steps within the SAME session, but each step
-- should still be run and read one at a time.
-- ====================================================================

-- STEP 1: capture a clean timestamp BEFORE the "accident"
DECLARE @RecoveryPointTime DATETIME2 = SYSDATETIME();
SELECT @RecoveryPointTime AS CapturedAt;
-- NOTE: do NOT run GO after this line if you want @RecoveryPointTime
-- to survive into Steps 2/3 as a script variable -- in SSMS, re-run
-- this same DECLARE line together with Steps 2/3 as one selection,
-- or simply write the printed timestamp down and hardcode it below.

-- STEP 2: the "accident" -- delete the record live, on request
-- (example: deleting StaffID 7 -- substitute whatever's asked for)
-- DELETE FROM dbo.Staff WHERE StaffID = 7;
-- SELECT COUNT(*) AS ShouldBeZero FROM dbo.Staff WHERE StaffID = 7;

-- STEP 3: recover it, as DBA, using the matching sp_RecoverX
-- EXECUTE AS USER = 'demo_dba_user';
-- DECLARE @RSuccess BIT, @RMessage NVARCHAR(200);
-- EXEC dbo.sp_RecoverStaff @StaffID = 7, @AsOfDateTime = @RecoveryPointTime,
--     @Success = @RSuccess OUTPUT, @Message = @RMessage OUTPUT;
-- SELECT @RSuccess AS Success, @RMessage AS Message;
-- REVERT;
-- SELECT * FROM dbo.Staff WHERE StaffID = 7;
-- -- Expected: record is back, same StaffID, all fields intact
GO

-- Same 3-step pattern for the other 3 tables -- just swap the proc
-- and ID column:
--   Customer          -> sp_RecoverCustomer   @CustomerID
--   Account           -> sp_RecoverAccount    @AccountID
--   TransactionRecord -> sp_RecoverTransactionRecord @TransID


-- ====================================================================
-- POINT 8 -- "Add users / change permissions live, show it's
-- captured in the audit"
-- Improvisational -- reusable pattern, worked through once.
-- ====================================================================

-- 8a. Live example: create a brand new Bank Officer through the
-- proper channel -- this ALSO auto-provisions their login (see
-- sp_ManageStaff's login-provisioning behavior)
EXECUTE AS USER = 'demo_manager_user';
DECLARE @Success BIT, @Expired BIT, @Message NVARCHAR(200);
EXEC sp_Login 'staff_faridosman', 'Test1234!', @Success OUTPUT, @Expired OUTPUT, @Message OUTPUT;
DECLARE @NewSuccess BIT, @NewMessage NVARCHAR(200);
EXEC dbo.sp_ManageStaff @StaffID = NULL, @StaffName = 'Demo Live Officer', @Position = 'Bank Officer',
    @Branch = 'Subang', @Phone = '0161112222', @Salary = 4200.00, @IsActive = 1,
    @Success = @NewSuccess OUTPUT, @Message = @NewMessage OUTPUT;
SELECT @NewSuccess AS Success, @NewMessage AS Message;
REVERT;
GO
-- Expected: Success = 1, @NewMessage includes a generated username
-- + temporary password

-- 8b. Immediately show this got captured -- BOTH the Staff INSERT
-- and the UserLogin INSERT that provisioned their login
SELECT TOP 2 TableName, RecordID, ChangedBy, ActionType, Activity
FROM AuditSchema.AuditLog
WHERE TableName IN ('Staff', 'UserLogin')
ORDER BY LogID DESC;
GO
-- Expected: 2 rows -- one Staff INSERT, one UserLogin INSERT,
-- both timestamped seconds apart, same ChangedBy

-- 8c. Live example: change a role membership, then show it audited
ALTER ROLE Bank_Officer ADD MEMBER demo_officer_user;  -- already a member; shown for illustration
GO

EXECUTE AS USER = 'demo_dba_user';
EXEC dbo.sp_DBA_ViewAuditFile;
REVERT;
GO
-- On a genuinely new principal, this triggers C6's permission-
-- change audit group

PRINT 'Main walkthrough complete. Point 6 (cross-instance restore) is a separate section below.';
GO


-- ====================================================================
-- POINT 6 -- "Restore an encrypted backup on ANOTHER SQL instance,
-- prove the data is accessible"
-- Genuinely separate from everything above -- this runs partly on
-- THIS instance (source) and partly on a DIFFERENT instance
-- (target). Do this rehearsal at least once before demo day.
-- ====================================================================

-- ---------- ON THE SOURCE INSTANCE (this one) ----------

-- 6a. Find the most recent Full backup file to restore from
SELECT TOP 1 bs.backup_start_date, bmf.physical_device_name
FROM msdb.dbo.backupset bs
JOIN msdb.dbo.backupmediafamily bmf ON bs.media_set_id = bmf.media_set_id
WHERE bs.database_name = 'SmartBankDB' AND bs.type = 'D'
ORDER BY bs.backup_start_date DESC;
GO
-- Copy the physical_device_name this returns -- you'll need the
-- actual .bak FILE copied to the target machine

-- 6b. Export the backup encryption certificate + private key --
-- REQUIRED on the target instance before restore will work at all.
-- (This was already done once during setup -- Part 10, [B6] -- but
-- shown here again since it's the step most likely to be forgotten
-- before a demo.)
USE master;
GO
-- BACKUP CERTIFICATE BackupEncryptCert
--     TO FILE = 'C:\SQLKeys\BackupEncryptCert.cer'
--     WITH PRIVATE KEY (
--         FILE = 'C:\SQLKeys\BackupEncryptCert.pvk',
--         ENCRYPTION BY PASSWORD = 'SmartBank_KeyBackup_P@ss2026!'
--     );
-- GO
-- Copy BOTH the .bak file AND BackupEncryptCert.cer/.pvk to the
-- target machine before proceeding.

-- ---------- ON THE TARGET INSTANCE (a different SQL Server) ----------

-- 6c. The target instance needs its own master key first
-- IF NOT EXISTS (SELECT 1 FROM sys.symmetric_keys WHERE name = '##MS_DatabaseMasterKey##')
--     CREATE MASTER KEY ENCRYPTION BY PASSWORD = 'TargetInstance_DMK_P@ss2026!';
-- GO

-- 6d. Import the certificate + private key copied over in 6b --
-- WITHOUT this, RESTORE will fail with a decryption error, since
-- the target has no way to read an encrypted backup otherwise
-- CREATE CERTIFICATE BackupEncryptCert
--     FROM FILE = 'C:\SQLKeys\BackupEncryptCert.cer'
--     WITH PRIVATE KEY (
--         FILE = 'C:\SQLKeys\BackupEncryptCert.pvk',
--         DECRYPTION BY PASSWORD = 'SmartBank_KeyBackup_P@ss2026!'
--     );
-- GO

-- 6e. Restore -- substitute the actual copied file path
-- RESTORE DATABASE SmartBankDB_Restored
--     FROM DISK = 'C:\RestoreTest\SmartBankDB_Full_<timestamp>.bak'
--     WITH MOVE 'SmartBankDB' TO 'C:\RestoreTest\SmartBankDB_Restored.mdf',
--          MOVE 'SmartBankDB_log' TO 'C:\RestoreTest\SmartBankDB_Restored_log.ldf',
--          RECOVERY;
-- GO

-- 6f. Prove the restored data is genuinely accessible
-- USE SmartBankDB_Restored;
-- GO
-- SELECT COUNT(*) AS StaffCount FROM dbo.Staff;
-- SELECT COUNT(*) AS CustomerCount FROM dbo.Customer;
-- -- Expected: real row counts, matching the source database at
-- -- backup time -- proves the encrypted backup is genuinely
-- -- restorable and readable, not corrupted or permanently locked
-- -- by encryption

PRINT 'Demo walkthrough file complete.';
GO
