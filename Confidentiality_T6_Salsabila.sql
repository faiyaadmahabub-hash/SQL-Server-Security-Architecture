-- SALSABILA (TP078641) CONFIDENTIALITY T6 // SQL SERVER TRACKING 


-- IMPLEMENTATION >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
/* ================================================================
   Task C6: Turn on SQL Server's built-in tracking for logins, schema
   changes, permission changes, and sensitive read access.

   Report reference : Section 3.5, Table 3 (Audit Matrix)
   Weakness addressed: Weakness 12 (no monitoring of failed auth,
   no server-level audit spec, no logging of read access)

   Run this as a sysadmin login. Create the folder below on the
   SQL Server host BEFORE running:  C:\SmartBankAudit\
   ================================================================ */

USE master;
GO

-- ================================================================
-- [C6.1] SERVER AUDIT OBJECT
-- Defines WHERE audit records are written and how failures behave.
-- This is the shared container every specification below plugs into.
-- ================================================================

-- The server audit must be OFF before you can change its file target
ALTER SERVER AUDIT SmartBank_ServerAudit WITH (STATE = OFF);
GO

ALTER SERVER AUDIT SmartBank_ServerAudit
TO FILE
(
    FILEPATH = 'C:\SQLAudit\',
    MAXSIZE = 100 MB,
    MAX_ROLLOVER_FILES = 50,
    RESERVE_DISK_SPACE = OFF
);
GO

ALTER SERVER AUDIT SmartBank_ServerAudit WITH (STATE = ON);
GO

-- Confirm it's now pointing at the right place
SELECT name, status_desc
FROM sys.dm_server_audit_status;

-- }}

-- ================================================================
-- [C6.2] SERVER AUDIT SPECIFICATION — LOGIN / LOGOUT
-- Report Table 3, row 1: "Login / logout attempts (success and failure)"
-- Captures: SUCCEEDED_LOGIN_GROUP, FAILED_LOGIN_GROUP, LOGOUT_GROUP
-- Addresses Weakness 12: no monitoring of failed authentication attempts
-- ================================================================
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

-- ================================================================
-- [C6.3 / C6.4 / C6.5] DATABASE AUDIT SPECIFICATION — COMBINED
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
-- ================================================================
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


-- ================================================================
-- [C6.6] ENABLE THE SERVER AUDIT AND ALL SPECIFICATIONS
-- Nothing above records anything until each object is turned ON.
-- ================================================================
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


-- ================================================================
-- [C6.7] RESTRICT AUDIT VISIBILITY TO THE DBA ROLE ONLY
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
-- ================================================================
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

-- Lock down execution rights: DO NOT deny to 'public' — every user,
-- including DBA role members, is automatically a member of public,
-- and an explicit DENY always overrides a GRANT from any other role,
-- even a more specific one like DBA. Simply never granting EXECUTE
-- to anyone but DBA is sufficient — SQL Server denies by default.
GRANT EXECUTE ON dbo.sp_DBA_ViewAuditFile TO DBA;
GO


-- ================================================================
-- [C6.7b] IMPORTANT — CONTROL SERVER REQUIREMENT
-- sys.fn_get_audit_file() requires CONTROL SERVER permission on
-- the caller, with no smaller/more specific permission available.
-- CONTROL SERVER is a SERVER-level permission tied to a LOGIN —
-- it cannot be granted to a database role like DBA, and it is NOT
-- automatically inherited just by being a member of that role.
--
-- This means: being added to the DBA database role satisfies the
-- IS_MEMBER('DBA') check inside the procedure, but is NOT enough
-- on its own to successfully read the audit file. Each real LOGIN
-- that will act as a DBA must ALSO be individually granted
-- CONTROL SERVER at the server level, e.g.:
--
--     USE master;
--     GRANT CONTROL SERVER TO <real_dba_login_name>;
--
-- COORDINATION FLAG for Person B: whenever a new Staff member with
-- Position = 'DBA' is provisioned a login (Section 3.1/4.1 login
-- system), that login also needs this grant to fully exercise
-- audit-viewing rights. Flag this in the login provisioning
-- procedure or as a manual DBA onboarding step.
--
-- Callers must also connect via EXECUTE AS LOGIN (not EXECUTE AS
-- USER) or a native login session — EXECUTE AS USER only carries
-- database-level identity and does not carry CONTROL SERVER with
-- it even if the underlying login has been granted it.
-- ================================================================
PRINT 'Reminder: grant CONTROL SERVER individually to each real DBA login — see comment above [C6.7b].';
GO

PRINT 'C6 — SQL Server Audit setup complete. Server audit and all 4 specifications are ON.';

-- TEST CASE >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
/* ================================================================
   TASK C6 TEST CASES
   Run this AFTER C6_SQL_Server_Audit_Setup.sql has executed
   successfully and the audit is confirmed ON.

   A few tests (T-C6.2, T-C6.3) involve actions OUTSIDE this script
   (opening a new login connection) — instructions are included as
   comments at the right point, then the script resumes to verify
   the result.

   IMPORTANT: your own sysadmin/Windows login CANNOT be used to
   test sp_DBA_ViewAuditFile directly — it bypasses GRANT/DENY
   permission checks, but NOT the manual IS_MEMBER('DBA') check
   inside the procedure, and it isn't (and can't be) a member of
   the DBA role. So every call to the procedure below runs through
   a dedicated test_dba_user via EXECUTE AS ... REVERT.
   ================================================================ */

USE SmartBankDB;
GO


/* ================================================================
   ONE-TIME SETUP — only needed once, skip if already done
   Creates a dedicated, NON-sysadmin login/user for testing as a
   genuine DBA-role member.
   ================================================================ */
USE master;
GO

IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name = 'test_dba_login')
    CREATE LOGIN test_dba_login WITH PASSWORD = 'Str0ngTestPass!123';
GO

-- CONTROL SERVER is required for sp_DBA_ViewAuditFile to succeed
-- (see [C6.7b] in the setup script) — granted here since this is
-- test-specific infrastructure, not part of the shared mechanism.
-- In the real system, Person B's login provisioning must grant this
-- to each actual DBA-role login individually.
IF NOT EXISTS (
    SELECT 1 FROM sys.server_permissions perm
    JOIN sys.server_principals pr ON perm.grantee_principal_id = pr.principal_id
    WHERE pr.name = 'test_dba_login' AND perm.permission_name = 'CONTROL SERVER'
)
    GRANT CONTROL SERVER TO test_dba_login;
GO

USE SmartBankDB;
GO

IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = 'test_dba_user')
    CREATE USER test_dba_user FOR LOGIN test_dba_login;
GO

IF NOT EXISTS (SELECT 1 FROM sys.database_role_members drm
                JOIN sys.database_principals r ON drm.role_principal_id = r.principal_id
                JOIN sys.database_principals m ON drm.member_principal_id = m.principal_id
                WHERE r.name = 'DBA' AND m.name = 'test_dba_user')
    ALTER ROLE DBA ADD MEMBER test_dba_user;
GO

-- Confirm membership from inside a test_dba_user session
EXECUTE AS USER = 'test_dba_user';
SELECT IS_MEMBER('DBA');   -- should return 1
REVERT;
GO


/* ================================================================ 
   T-C6.1 — POSITIVE: confirm all audit objects exist and are ON
   ================================================================ */
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
PRINT '--- T-C6.2: after logging in successfully from another window, run below ---';
 
EXECUTE AS LOGIN = 'test_dba_login';
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
 
EXECUTE AS LOGIN = 'test_dba_login';
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
 
EXECUTE AS LOGIN = 'test_dba_login';
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
 
EXECUTE AS LOGIN = 'test_dba_login';
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
 
EXECUTE AS LOGIN = 'test_dba_login';
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
 
EXECUTE AS LOGIN = 'test_dba_login';
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
-- Expected: Msg 229 "The EXECUTE permission was denied..." — this
-- means SQL Server's own GRANT/DENY layer blocked the call BEFORE
-- the procedure's code even started running (the outer of two
-- defense layers). The internal IF IS_MEMBER('DBA')=0 THROW check
-- (error 51000) is a backup layer that only fires if someone
-- somehow has EXECUTE permission without being a DBA role member —
-- it won't be reached in this test since Test_NonDBA is blocked
-- one layer earlier.
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
 