-- SALSABILA AURELIA OKTANIOPUTRI (TP078641) CONFIDENTIALITY

/* ____________________________________________________________________________________________________________________
   C6: SQL SERVER AUDIT >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
	- Turn on sql server audit: track logins, schema changes, permission changes, sensitive read access.
	- Report: Section 3.5 Table 3 (Audit Matrix)
	- Weakness 12: no monitoring of failed auth, no server level audit spec, no logging of read access etc */


-- Implementation >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

USE master;
GO

-- [C6.1] SERVER AUDIT OBJECT  ____________________________________________________
-- Defines WHERE audit records are written and how failures behave.
-- This is the shared container every specification below plugs into.

IF EXISTS (SELECT 1 FROM sys.server_audits WHERE name = 'SmartBank_ServerAudit')
    DROP SERVER AUDIT SmartBank_ServerAudit;
GO

CREATE SERVER AUDIT SmartBank_ServerAudit
TO FILE
(
    FILEPATH            = 'C:\SQLAudit\',   -- "C:\Users\asus\SQL-Server-Security-Architecture"
    MAXSIZE             = 100 MB,
    MAX_ROLLOVER_FILES  = 50,
    RESERVE_DISK_SPACE  = OFF
)
WITH
(
    QUEUE_DELAY  = 1000,      -- ms the engine may buffer before writing to disk
    ON_FAILURE   = CONTINUE   -- don't take the whole database offline if the audit write fails
);
GO


-- [C6.2] SERVER AUDIT SPECIFICATION — LOGIN / LOGOUT  ____________________________________________________
-- Report Table 3, row 1: "Login / logout attempts (success and failure)"
-- Captures: SUCCEEDED_LOGIN_GROUP, FAILED_LOGIN_GROUP, LOGOUT_GROUP
-- Addresses Weakness 12: no monitoring of failed authentication attempts

IF EXISTS (SELECT 1 FROM sys.server_audit_specifications WHERE name = 'SmartBank_LoginAuditSpec')
    DROP SERVER AUDIT SPECIFICATION SmartBank_LoginAuditSpec;
GO

CREATE SERVER AUDIT SPECIFICATION SmartBank_LoginAuditSpec
FOR SERVER AUDIT SmartBank_ServerAudit
    ADD (SUCCESSFUL_LOGIN_GROUP),
    ADD (FAILED_LOGIN_GROUP),
    ADD (LOGOUT_GROUP)
WITH (STATE = OFF);  -- switched ON in [C6.6]
GO


USE SmartBankDB;
GO

-- [C6.3 / C6.4 / C6.5] DATABASE AUDIT SPECIFICATION — COMBINED  ____________________________________________________
-- SQL Server only permits ONE database audit specification per
-- (server audit, database) pair, so schema changes, permission
-- changes, and sensitive SELECT access are combined here as
-- separate ADD clauses inside a single specification.
--
-- [C6.3] Schema changes        — Report Table 3, row 2
-- [C6.4] Permission changes    — Report Table 3, row 3
-- [C6.5] Sensitive read access — Report Table 3, row 4
-- Addresses Weakness 12 (no server-level audit spec, no logging
-- of read access)

IF EXISTS (SELECT 1 FROM sys.database_audit_specifications WHERE name = 'SmartBank_DatabaseAuditSpec')
    DROP DATABASE AUDIT SPECIFICATION SmartBank_DatabaseAuditSpec;
GO
 
CREATE DATABASE AUDIT SPECIFICATION SmartBank_DatabaseAuditSpec
FOR SERVER AUDIT SmartBank_ServerAudit
    -- [C6.3] schema changes
    ADD (SCHEMA_OBJECT_CHANGE_GROUP),
    ADD (DATABASE_OBJECT_CHANGE_GROUP),
    -- [C6.4] permission changes
    ADD (DATABASE_PERMISSION_CHANGE_GROUP),
    ADD (SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP),
    -- [C6.5] sensitive read access
    ADD (SELECT ON OBJECT::dbo.Customer  BY public),
    ADD (SELECT ON OBJECT::dbo.Account   BY public),
    ADD (SELECT ON OBJECT::dbo.UserLogin BY public)
WITH (STATE = OFF);
GO
 
-- [C6.6] ENABLE THE SERVER AUDIT AND ALL SPECIFICATIONS ____________________________________________________
-- Nothing above records anything until each object is turned ON.

USE master;
GO
ALTER SERVER AUDIT SmartBank_ServerAudit WITH (STATE = ON);
GO
ALTER SERVER AUDIT SPECIFICATION SmartBank_LoginAuditSpec WITH (STATE = ON);
GO
 
USE SmartBankDB;
GO
ALTER DATABASE AUDIT SPECIFICATION SmartBank_DatabaseAuditSpec WITH (STATE = ON);
GO

-- [C6.7] RESTRICT AUDIT VISIBILITY TO THE DBA ROLE ONLY  ____________________________________________________
-- Report ref: Section 3.5 — "Both auditing mechanisms store their
-- records in protected locations that only the DBA role can
-- access." Table 3's Access column reads "DBA only" for all 4 rows.
--
-- Raw audit records can only be read via sys.fn_get_audit_file(),
-- which itself requires CONTROL SERVER permission — application
-- roles (Bank_Manager/Bank_Officer/Customer) are never granted
-- this, so they cannot read the audit trail directly. This wrapper
-- procedure gives the DBA role a controlled, single entry point
-- instead of handing out raw CONTROL SERVER permission to a person.
--
-- Uses Person B's actual role name from Task 3 (role setup):
-- [DBA]  -- confirmed, no "db_" prefix. Role already exists,
-- created by B — no placeholder needed here.

CREATE OR ALTER PROCEDURE dbo.sp_DBA_ViewAuditFile
AS
BEGIN
    SET NOCOUNT ON;
 
    -- Application-level gate: only members of the DBA role may run this at all
    IF IS_MEMBER('DBA') = 0
    BEGIN
        THROW 51000, 'Access denied: audit records are restricted to the DBA role.', 1;
        RETURN;
    END
 
    SELECT
        event_time,
        action_id,
        succeeded,
        server_principal_name,
        database_name,
        object_name,
        statement
    FROM sys.fn_get_audit_file('C:\SQLAudit\*.sqlaudit', DEFAULT, DEFAULT)
    ORDER BY event_time DESC;
END;
GO

-- creating DB (abd's part)
USE SmartBankDB;
GO

IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = 'DBA' AND type = 'R')
    CREATE ROLE DBA;
GO

-- confirm it now exists
SELECT name, type_desc 
FROM sys.database_principals 
WHERE type = 'R';
 
-- Lock down execution rights: deny everyone by default, then
-- explicitly re-grant only to the DBA role.
DENY EXECUTE ON dbo.sp_DBA_ViewAuditFile TO public;
GO
GRANT EXECUTE ON dbo.sp_DBA_ViewAuditFile TO DBA;
GO
 
PRINT 'C6 — SQL Server Audit setup complete. Server audit and all 4 specifications are ON.';

-- Test Case >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

-- One time setup : test set up account
--    Creates a dedicated, NON-sysadmin login/user for testing as a genuine DBA-role member.
USE master;
GO
CREATE LOGIN test_dba_login WITH PASSWORD = 'Str0ngTestPass!123';
GO

USE SmartBankDB;
GO
CREATE USER test_dba_user FOR LOGIN test_dba_login;
GO
-- Add this user to the DBA role
ALTER ROLE DBA ADD MEMBER test_dba_user;
GO
-- Confirm membership from inside a test_dba_user session
EXECUTE AS USER = 'test_dba_user';
SELECT IS_MEMBER('DBA');   -- should return 1
REVERT;
GO


-- [T-C6.1] — POSITIVE: confirm all audit objects exist and are ON ___________________________________________________________
 
PRINT '--- T-C6.1: checking audit objects are enabled ---';

SELECT name, is_state_enabled 
FROM sys.server_audits;                      -- expect 1 row, is_state_enabled = 1

SELECT name, is_state_enabled 
FROM sys.server_audit_specifications;         -- expect 1 row, is_state_enabled = 1

SELECT name, is_state_enabled 
FROM sys.database_audit_specifications;       -- expect 1 row (SmartBank_DatabaseAuditSpec), is_state_enabled = 1
GO


/* ================================================================
   T-C6.2 — POSITIVE: successful login gets captured
   MANUAL STEP: open a NEW SSMS connection window using VALID
   credentials for any existing login, let it connect, then come
   back to THIS window and run the block below.
   ================================================================ */


-- checking
-- 1. Who is your actual SQL Server LOGIN (server-level identity)?
SELECT SUSER_SNAME() AS current_login;

-- 2. Who are you mapped to as a USER inside SmartBankDB (database-level identity)?
USE SmartBankDB;
SELECT USER_NAME() AS current_db_user;

-- 3. Are you a sysadmin?
SELECT IS_SRVROLEMEMBER('sysadmin') AS am_i_sysadmin;   -- 1 = yes, 0 = no

-- 4. Does test_dba_login exist as a server login at all, and is it enabled?
SELECT name, is_disabled 
FROM sys.sql_logins 
WHERE name = 'test_dba_login';

-- 5. Does test_dba_user exist inside SmartBankDB, and what login is it tied to?
SELECT dp.name AS db_user, sp.name AS mapped_login
FROM sys.database_principals dp
LEFT JOIN sys.server_principals sp ON dp.sid = sp.sid
WHERE dp.name = 'test_dba_user';

-- 6. Is test_dba_user actually a member of the DBA role?
SELECT r.name AS role_name, m.name AS member_name
FROM sys.database_role_members drm
JOIN sys.database_principals r ON drm.role_principal_id = r.principal_id
JOIN sys.database_principals m ON drm.member_principal_id = m.principal_id
WHERE r.name = 'DBA';

-- 7. Is SQL Server even set up to allow SQL logins (not just Windows auth)?
SELECT SERVERPROPERTY('IsIntegratedSecurityOnly') AS windows_auth_only;
-- 1 = ONLY Windows auth allowed (this would explain your failed login!)
-- 0 = Mixed mode (both Windows + SQL logins allowed) — needed for test_dba_login to work


-- checking
-- reset query window
REVERT;
GO
SELECT SUSER_SNAME() AS current_login, USER_NAME() AS current_db_user;

SELECT SERVERPROPERTY('IsIntegratedSecurityOnly') AS windows_auth_only;
-- should now return 0

SELECT name, is_disabled 
FROM sys.sql_logins 
WHERE name = 'test_dba_login';

-- another fix

-- Are you currently impersonating someone?
SELECT SUSER_SNAME() AS server_login, USER_NAME() AS db_user;
USE SmartBankDB;
GO

REVERT;
GO
-- run REVERT a couple times if needed until it errors "no impersonation active" — 
-- that error means you're already clear
SELECT SUSER_SNAME() AS server_login, USER_NAME() AS db_user;
-- should now show your real login and dbo

-- Remove the conflicting DENY (this cancels it, doesn't add a new grant)
REVOKE EXECUTE ON dbo.sp_DBA_ViewAuditFile FROM public;
GO

-- Confirm the DBA grant is still in place (harmless to re-run)
GRANT EXECUTE ON dbo.sp_DBA_ViewAuditFile TO DBA;
GO

REVOKE EXECUTE ON dbo.sp_DBA_ViewAuditFile FROM public;
GO
GRANT EXECUTE ON dbo.sp_DBA_ViewAuditFile TO DBA;
GO

-- test case 
PRINT '--- T-C6.2: after logging in successfully from another window, run below ---';
EXECUTE AS USER = 'test_dba_user';
EXEC dbo.sp_DBA_ViewAuditFile;
-- Expected: a row with action_id = 'LGIS' (login succeeded), succeeded = 1
REVERT;
GO

/* ================================================================
   T-C6.3 — POSITIVE: failed login attempt gets captured
   MANUAL STEP: open a NEW SSMS connection window and attempt to
   log in with a WRONG password for any existing login (connection
   will be refused — that's expected). Then return here.
   ================================================================ */
PRINT '--- T-C6.3: after a failed login attempt, run below ---';

EXECUTE AS USER = 'test_dba_user';
EXEC dbo.sp_DBA_ViewAuditFile;
-- Expected: a row with action_id = 'LGIF' (login failed), succeeded = 0
REVERT;
GO


/* ================================================================
   T-C6.4 — POSITIVE: schema change gets captured
   (CREATE/DROP TABLE run as your normal sysadmin session — that's
   fine, schema changes aren't restricted to the DBA role here)
   ================================================================ */
PRINT '--- T-C6.4: creating and dropping a dummy table ---';

CREATE TABLE dbo.Test_AuditDummy (ID INT);
GO
DROP TABLE dbo.Test_AuditDummy;
GO

EXECUTE AS USER = 'test_dba_user';
EXEC dbo.sp_DBA_ViewAuditFile;
-- Expected: two rows referencing object_name = 'Test_AuditDummy' 
-- (one CREATE, one DROP), with the exact statement text captured
REVERT;
GO


/* ================================================================
   T-C6.5 — POSITIVE: permission change gets captured
   ================================================================ */
PRINT '--- T-C6.5: granting and revoking a test permission ---';

GRANT SELECT ON dbo.Staff TO DBA;
GO
REVOKE SELECT ON dbo.Staff FROM DBA;
GO

EXECUTE AS USER = 'test_dba_user';
EXEC dbo.sp_DBA_ViewAuditFile;
-- Expected: two rows referencing dbo.Staff, showing the GRANT and REVOKE
REVERT;
GO


/* ================================================================
   T-C6.6 — POSITIVE: sensitive SELECT access gets captured
   ================================================================ */
PRINT '--- T-C6.6: querying Customer and UserLogin ---';

SELECT * FROM dbo.Customer;
GO
SELECT * FROM dbo.UserLogin;
GO

EXECUTE AS USER = 'test_dba_user';
EXEC dbo.sp_DBA_ViewAuditFile;
-- Expected: rows with object_name = 'Customer' and object_name = 'UserLogin',
-- statement column shows the SELECT that was run
REVERT;
GO


/* ================================================================
   T-C6.7 — POSITIVE: DBA role member CAN view the audit trail
   (confirms the procedure runs cleanly for a genuine DBA member,
   consolidating everything captured above)
   ================================================================ */
PRINT '--- T-C6.7: confirming DBA member can run the wrapper ---';

EXECUTE AS USER = 'test_dba_user';
EXEC dbo.sp_DBA_ViewAuditFile;
-- Expected: full result set returned, no error thrown
REVERT;
GO


/* ================================================================
   T-C6.8 — NEGATIVE: non-DBA is blocked from the wrapper procedure
   ================================================================ */
PRINT '--- T-C6.8: testing as a non-DBA user ---';

CREATE USER Test_NonDBA WITHOUT LOGIN;
GO

EXECUTE AS USER = 'Test_NonDBA';
EXEC dbo.sp_DBA_ViewAuditFile;
-- Expected: Error 51000 "Access denied: audit records are restricted 
-- to the DBA role." is thrown
REVERT;   -- return to your normal session — IMPORTANT, do not skip
GO


/* ================================================================
   T-C6.9 — NEGATIVE: non-DBA has no EXECUTE permission on the wrapper
   ================================================================ */
PRINT '--- T-C6.9: checking permissions as non-DBA user ---';

EXECUTE AS USER = 'Test_NonDBA';
SELECT * FROM fn_my_permissions('dbo.sp_DBA_ViewAuditFile', 'OBJECT');
-- Expected: EXECUTE does NOT appear in the results
REVERT;
GO


/* ================================================================
   T-C6.10 — NEGATIVE: non-DBA cannot bypass the wrapper by going
   straight to sys.fn_get_audit_file()
   ================================================================ */
PRINT '--- T-C6.10: attempting direct raw file access as non-DBA user ---';

EXECUTE AS USER = 'Test_NonDBA';
SELECT * FROM sys.fn_get_audit_file('C:\SQLAudit\*.sqlaudit', DEFAULT, DEFAULT);
-- Expected: permission error (requires CONTROL SERVER)
REVERT;
GO


/* ================================================================
   CLEANUP — remove test artifacts so they don't linger
   (test_dba_login / test_dba_user are left in place — you'll
   likely reuse them for future confidentiality task tests too)
   ================================================================ */
PRINT '--- Cleaning up test user ---';

DROP USER Test_NonDBA;
GO

PRINT 'C6 test suite complete.';