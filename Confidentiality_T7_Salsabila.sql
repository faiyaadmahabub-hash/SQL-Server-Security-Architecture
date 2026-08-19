-- SALSABILA (TP078641) CONFIDENTIALITY T7 // CONFIRM LOGIN LOGOUT AUDIT
/* ================================================================
   Task C7: Confirm login/logout audit captures every field Table 3 requires,
   and remains restricted to the DBA role only.

   Report reference : Section 3.5, Table 3 (Audit Matrix, row 1)
   Weakness addressed: Weakness 12
   ================================================================ */

USE SmartBankDB;
GO

/* ================================================================
   [C7.1] FOCUSED LOGIN/LOGOUT AUDIT VIEWING PROCEDURE
   Filters to only login/logout action IDs, and explicitly includes
   client_ip (the audit file's "client host" field) — the one
   required field C6's general-purpose procedure never displayed.
   ================================================================ */
CREATE OR ALTER PROCEDURE dbo.sp_DBA_ViewLoginAudit
AS
BEGIN
    SET NOCOUNT ON;

    IF IS_MEMBER('DBA') = 0
    BEGIN
        THROW 51004, 'Access denied: login audit records are restricted to the DBA role.', 1;
        RETURN;
    END

    SELECT
        event_time,
        server_principal_name AS LoginName,
        client_ip AS ClientHost,
        CASE action_id
            WHEN 'LGIS' THEN 'Login Succeeded'
            WHEN 'LGIF' THEN 'Login Failed'
            WHEN 'LGO'  THEN 'Logout'
            ELSE action_id
        END AS EventType,
        succeeded AS Succeeded
    FROM sys.fn_get_audit_file('C:\SQLAudit\*.sqlaudit', DEFAULT, DEFAULT)
    WHERE action_id IN ('LGIS', 'LGIF', 'LGO')
    ORDER BY event_time DESC;
END;
GO

/* ================================================================
   [C7.2] ACCESS RESTRICTION
   ================================================================ */
GRANT EXECUTE ON dbo.sp_DBA_ViewLoginAudit TO DBA;
GO

PRINT 'C7 — focused login/logout audit verification procedure ready.';

-- TEST CASE >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>.
/* ================================================================
   Reuses test_dba_login from C6 (must already exist and be a
   member of DBA with CONTROL SERVER granted — see C6 setup).
   ================================================================ */

USE SmartBankDB;
GO

/* ================================================================
   ONE-TIME SETUP — confirm test_dba_login still exists (from C6);
   recreate defensively if this is a fresh session. Also creates a
   non-DBA test user for the negative test.
   ================================================================ */
USE master;
GO
IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name = 'test_dba_login')
BEGIN
    CREATE LOGIN test_dba_login WITH PASSWORD = 'Str0ngTestPass!123';
    GRANT CONTROL SERVER TO test_dba_login;
END
IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name = 'test_officer_login')
    CREATE LOGIN test_officer_login WITH PASSWORD = 'Str0ngTestPass!123';
GO

USE SmartBankDB;
GO
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = 'test_dba_user')
    CREATE USER test_dba_user FOR LOGIN test_dba_login;
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = 'test_officer_user')
    CREATE USER test_officer_user FOR LOGIN test_officer_login;
GO

IF NOT EXISTS (SELECT 1 FROM sys.database_role_members drm
                JOIN sys.database_principals r ON drm.role_principal_id = r.principal_id
                JOIN sys.database_principals m ON drm.member_principal_id = m.principal_id
                WHERE r.name = 'DBA' AND m.name = 'test_dba_user')
    ALTER ROLE DBA ADD MEMBER test_dba_user;
IF NOT EXISTS (SELECT 1 FROM sys.database_role_members drm
                JOIN sys.database_principals r ON drm.role_principal_id = r.principal_id
                JOIN sys.database_principals m ON drm.member_principal_id = m.principal_id
                WHERE r.name = 'Bank_Officer' AND m.name = 'test_officer_user')
    ALTER ROLE Bank_Officer ADD MEMBER test_officer_user;
GO

/* ================================================================
   T-C7.1 — POSITIVE: LoginName field is populated
   ================================================================ */
PRINT '--- T-C7.1: checking LoginName is captured ---';

EXECUTE AS LOGIN = 'test_dba_login';
EXEC dbo.sp_DBA_ViewLoginAudit;
REVERT;
-- Expected: LoginName column is populated (not NULL/blank) for
-- every row
GO

/* ================================================================
   T-C7.2 — POSITIVE: ClientHost field is populated
   MANUAL STEP: if ClientHost appears blank/NULL for all rows,
   open a NEW SSMS connection (any login) to generate a fresh
   login event, then re-run this test — some local/shared-memory
   connections may report an empty client_ip depending on the
   connection protocol used.
   ================================================================ */
PRINT '--- T-C7.2: checking ClientHost is captured ---';

EXECUTE AS LOGIN = 'test_dba_login';
EXEC dbo.sp_DBA_ViewLoginAudit;
REVERT;
-- Expected: ClientHost column shows a value for at least some rows
GO

/* ================================================================
   T-C7.3 — POSITIVE: EventType and Succeeded correctly distinguish
   success vs failure
   ================================================================ */
PRINT '--- T-C7.3: checking EventType/Succeeded correctly labeled ---';

EXECUTE AS LOGIN = 'test_dba_login';
EXEC dbo.sp_DBA_ViewLoginAudit;
REVERT;
-- Expected: rows show EventType = 'Login Succeeded' with
-- Succeeded = 1, EventType = 'Login Failed' with Succeeded = 0,
-- and EventType = 'Logout' with Succeeded = 1
-- (If no failed logins exist yet in your audit history, generate
-- one manually: open a new SSMS connection with a deliberately
-- wrong password, then re-run this test.)
GO

/* ================================================================
   T-C7.4 — POSITIVE: Timestamp field is populated and reasonable
   ================================================================ */
PRINT '--- T-C7.4: checking event_time is populated ---';

EXECUTE AS LOGIN = 'test_dba_login';
EXEC dbo.sp_DBA_ViewLoginAudit;
REVERT;
-- Expected: event_time column shows valid, recent datetime values
-- for every row — confirms the 4th and final required field from
-- Table 3 row 1 is present, completing the field checklist:
-- LoginName (T-C7.1), ClientHost (T-C7.2), EventType/Succeeded
-- (T-C7.3), event_time (this test)
GO

/* ================================================================
   T-C7.5 — POSITIVE: DBA can view (re-confirmation for this
   specific procedure)
   ================================================================ */
PRINT '--- T-C7.5: confirming DBA member can run sp_DBA_ViewLoginAudit ---';

EXECUTE AS LOGIN = 'test_dba_login';
EXEC dbo.sp_DBA_ViewLoginAudit;
REVERT;
-- Expected: succeeds, returns rows, no error
GO

/* ================================================================
   T-C7.6 — NEGATIVE: non-DBA is blocked from this specific procedure
   ================================================================ */
PRINT '--- T-C7.6: Bank_Officer attempting to view login audit ---';

EXECUTE AS USER = 'test_officer_user';
EXEC dbo.sp_DBA_ViewLoginAudit;
-- Expected: Msg 229 EXECUTE permission denied
REVERT;
GO


/* ================================================================
   CLEANUP
   (test_dba_login/user and test_officer_login/user are shared
   across multiple tasks — intentionally left in place, not dropped)
   ================================================================ */
PRINT 'C7 test suite complete.';