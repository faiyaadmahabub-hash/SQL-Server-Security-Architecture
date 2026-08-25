-- ====================================================================
-- SmartBankDB -- EXHAUSTIVE FEATURE TEST SUITE
-- ====================================================================
-- This is the FULL test suite -- every positive/negative test case
-- built during development, extracted and reordered into the same
-- sequence as SmartBankDB_Codebase.sql (Task 1 -> Task 2 -> Task 3
-- -> ... -> Part 10). This is NOT the curated demo script -- that's
-- SmartBankDB_DemoWalkthrough.sql, which hits only what the
-- lecturer's 9-point checklist needs. This file is exhaustive: every
-- edge case, every negative test, every table's recovery scenario.
--
-- DEPENDS on SmartBankDB_Codebase.sql having been run first, in the
-- same database. This file is not standalone -- it tests objects
-- (procedures, views, triggers) that live in that file, and creates
-- its own test-only login/user principals (test_dba_login,
-- test_manager_user, etc.) that are never part of the real system.
--
-- Run block by block, in order, in the SAME SSMS session -- several
-- tests depend on state left behind by earlier ones (e.g. a test
-- password set on a seeded account, a test principal created
-- earlier in this same file). A few blocks are explicitly marked
-- "MANUAL STEP" or "run in a brand new query window" where
-- SESSION_CONTEXT persistence would otherwise give a false result --
-- those are called out inline where they occur.
-- ====================================================================


-- TASK #6 TEST CASES -- for Task #1 (Login System)
-- Run these immediately after building the code above, in the
-- SAME SSMS session, before moving on to Task #2. Highlight each
-- block below and press F5 to run just that block, so you can see
-- each result before running the next one.
-- ================================================================

-- Setup: give one seeded demo account a real password to test with
-- (only needs to be run ONCE, not every time you test)
DECLARE @TestSalt VARBINARY(32) = CRYPT_GEN_RANDOM(32);
DECLARE @TestPassword NVARCHAR(100) = 'Test1234!';

UPDATE dbo.UserLogin
SET Salt = @TestSalt,
    PasswordHash = HASHBYTES('SHA2_512', @TestSalt + CONVERT(VARBINARY(4000), @TestPassword)),
    PasswordLastChanged = SYSDATETIME()
WHERE Username = 'staff_hafizzainal';
GO

-- TEST CASE 1: Correct username + correct password -> should succeed
DECLARE @Success BIT, @Expired BIT, @Msg NVARCHAR(200);
EXEC sp_Login 'staff_hafizzainal', 'Test1234!', @Success OUTPUT, @Expired OUTPUT, @Msg OUTPUT;
SELECT @Success AS Success, @Expired AS Expired, @Msg AS Message;
-- Expected: Success = 1, Message = 'Login successful.'

-- TEST CASE 2: Correct username + WRONG password -> should fail, generic message
DECLARE @Success2 BIT, @Expired2 BIT, @Msg2 NVARCHAR(200);
EXEC sp_Login 'staff_hafizzainal', 'WrongPassword', @Success2 OUTPUT, @Expired2 OUTPUT, @Msg2 OUTPUT;
SELECT @Success2 AS Success, @Expired2 AS Expired, @Msg2 AS Message;
-- Expected: Success = 0, Message = 'Invalid username or password.'

-- TEST CASE 3: Unknown username -> should fail, SAME generic message as test 2
DECLARE @Success3 BIT, @Expired3 BIT, @Msg3 NVARCHAR(200);
EXEC sp_Login 'not_a_real_user', 'AnyPassword', @Success3 OUTPUT, @Expired3 OUTPUT, @Msg3 OUTPUT;
SELECT @Success3 AS Success, @Expired3 AS Expired, @Msg3 AS Message;
-- Expected: Success = 0, Message = 'Invalid username or password.'

-- TEST CASE 4: Lockout -- run TEST CASE 2 two more times (3 total wrong
-- attempts), then try the CORRECT password again
DECLARE @Success4 BIT, @Expired4 BIT, @Msg4 NVARCHAR(200);
EXEC sp_Login 'staff_hafizzainal', 'Test1234!', @Success4 OUTPUT, @Expired4 OUTPUT, @Msg4 OUTPUT;
SELECT @Success4 AS Success, @Expired4 AS Expired, @Msg4 AS Message;
-- Expected: Success = 0, Message = 'Account temporarily locked...'
-- even though the password is CORRECT this time -- proves lockout works

-- TEST CASE 4b: Password expiration -- demo-friendly technique
-- 90 real days obviously can't be waited out live. The correct way
-- to prove this works isn't to shrink PasswordExpiryDays (that
-- would mean demoing a fake, weaker system, not the real one) --
-- it's to backdate a test account's PasswordLastChanged so it's
-- already more than 90 days in the past. sp_Login's actual
-- DATEDIFF check then runs for real, against real data, and
-- genuinely computes ">90 days" -- nothing about the mechanism
-- itself is faked or shortcut, only the test fixture's timestamp
-- is engineered, same as backdating any date-based test case.
DECLARE @ExpSalt VARBINARY(32) = CRYPT_GEN_RANDOM(32);
DECLARE @ExpPassword NVARCHAR(100) = 'Test1234!';

UPDATE dbo.UserLogin
SET Salt = @ExpSalt,
    PasswordHash = HASHBYTES('SHA2_512', @ExpSalt + CONVERT(VARBINARY(4000), @ExpPassword)),
    PasswordLastChanged = DATEADD(DAY, -100, SYSDATETIME()),  -- 100 days ago > 90-day policy
    FailedLoginAttempts = 0, LockoutUntil = NULL
WHERE Username = 'staff_sitiaminah';

DECLARE @Success4b BIT, @Expired4b BIT, @Msg4b NVARCHAR(200);
EXEC sp_Login 'staff_sitiaminah', 'Test1234!', @Success4b OUTPUT, @Expired4b OUTPUT, @Msg4b OUTPUT;
SELECT @Success4b AS Success, @Expired4b AS Expired, @Msg4b AS Message;
-- Expected: Success = 0, Expired = 1, Message = 'Password has expired...'
-- -- the password typed was CORRECT (proves this isn't a lockout
-- or wrong-password rejection), it's specifically caught by the
-- expiry branch

SELECT TOP 1 * FROM AuditSchema.AuditLog WHERE TableName = 'UserLogin' AND Activity LIKE '%expired%' ORDER BY LogID DESC;
-- Expected: one REJECTED row, Activity shows the expiry message
-- plus "(Attempted as: staff_sitiaminah, Bank Officer)"

-- Cleanup: reset the clock so staff_sitiaminah isn't left
-- permanently "expired" for the rest of this script (or a live
-- demo) -- without this, every future login attempt on this
-- account would keep hitting the expiry branch, not just this test
UPDATE dbo.UserLogin
SET PasswordLastChanged = SYSDATETIME()
WHERE Username = 'staff_sitiaminah';

-- TEST CASE 5: SESSION_CONTEXT check -- after a successful login,
-- confirm the values were actually set
SELECT
    SESSION_CONTEXT(N'UserType')   AS SessionUserType,
    SESSION_CONTEXT(N'StaffID')    AS SessionStaffID,
    SESSION_CONTEXT(N'CustomerID') AS SessionCustomerID;
-- Expected: shows the logged-in user's UserType and StaffID (run this
-- right after a SUCCESSFUL login test, in the same query window)

-- TEST CASE 6: sp_Logout clears the session
EXEC sp_Logout;
SELECT
    SESSION_CONTEXT(N'UserType')   AS SessionUserType,
    SESSION_CONTEXT(N'StaffID')    AS SessionStaffID,
    SESSION_CONTEXT(N'CustomerID') AS SessionCustomerID;
-- Expected: all NULL now

USE SmartBankDB;
GO

-- ================================================================
-- TASK #6 TEST CASES -- for Task #2 (Change Password)
-- Run in the SAME query window, right after building the code
-- above. Highlight each block and press F5 individually.
-- ================================================================

-- TEST CASE 1: Correct old password + strong new password -> succeeds
DECLARE @Success BIT, @Msg NVARCHAR(200);
EXEC sp_ChangePassword 'staff_hafizzainal', 'Test1234!', 'NewPass99!', @Success OUTPUT, @Msg OUTPUT;
SELECT @Success AS Success, @Msg AS Message;
-- Expected: Success = 1, Message = 'Password changed successfully.'

-- TEST CASE 2: Confirm the NEW password actually works for login now
DECLARE @Success2 BIT, @Expired2 BIT, @Msg2 NVARCHAR(200);
EXEC sp_Login 'staff_hafizzainal', 'NewPass99!', @Success2 OUTPUT, @Expired2 OUTPUT, @Msg2 OUTPUT;
SELECT @Success2 AS Success, @Msg2 AS Message;
-- Expected: Success = 1

-- TEST CASE 3: Weak new password -> rejected before anything else is checked
DECLARE @Success3 BIT, @Msg3 NVARCHAR(200);
EXEC sp_ChangePassword 'staff_hafizzainal', 'NewPass99!', 'weak', @Success3 OUTPUT, @Msg3 OUTPUT;
SELECT @Success3 AS Success, @Msg3 AS Message;
-- Expected: Success = 0, complexity error message

-- TEST CASE 4: Wrong OLD password -> rejected, generic message
DECLARE @Success4 BIT, @Msg4 NVARCHAR(200);
EXEC sp_ChangePassword 'staff_hafizzainal', 'WrongOldPassword', 'AnotherStrong1!', @Success4 OUTPUT, @Msg4 OUTPUT;
SELECT @Success4 AS Success, @Msg4 AS Message;
-- Expected: Success = 0, 'Current password is incorrect.'

-- TEST CASE 5: Lockout via change-password -- run TEST CASE 4's block
-- two more times (3 wrong attempts total), then try again with
-- the CORRECT current password
DECLARE @Success5 BIT, @Msg5 NVARCHAR(200);
EXEC sp_ChangePassword 'staff_hafizzainal', 'NewPass99!', 'AnotherStrong1!', @Success5 OUTPUT, @Msg5 OUTPUT;
SELECT @Success5 AS Success, @Msg5 AS Message;
-- Expected: Success = 0, 'This account is temporarily locked...'
-- even with the CORRECT old password -- proves shared lockout works

-- ################################################################
-- Component: Assign test logins to each role
-- (For Task #6 testing only -- lets us actually connect AS each
-- role and prove the DENY rules work. Replace/remove these before
-- final submission if your team wants only "real" logins.)
-- ================================================================
CREATE LOGIN test_dba_login          WITH PASSWORD = 'TestDba123!';
CREATE LOGIN test_manager_login      WITH PASSWORD = 'TestMgr123!';
CREATE LOGIN test_officer_login      WITH PASSWORD = 'TestOfc123!';
CREATE LOGIN test_customer_login     WITH PASSWORD = 'TestCus123!';
GO

CREATE USER test_dba_user            FOR LOGIN test_dba_login;
CREATE USER test_manager_user        FOR LOGIN test_manager_login;
CREATE USER test_officer_user        FOR LOGIN test_officer_login;
CREATE USER test_customer_user       FOR LOGIN test_customer_login;
GO

ALTER ROLE DBA          ADD MEMBER test_dba_user;
ALTER ROLE Bank_Manager ADD MEMBER test_manager_user;
ALTER ROLE Bank_Officer ADD MEMBER test_officer_user;
ALTER ROLE Customer     ADD MEMBER test_customer_user;
GO


-- ================================================================
-- TASK #6 TEST CASES -- for Task #3 (Roles)
-- Some of these need to be run AS a specific test login, not as
-- your own admin account. Use EXECUTE AS USER to switch identity
-- inside the same window, then REVERT to switch back.
-- ================================================================

-- TEST CASE 1: Confirm all 4 roles were actually created
SELECT name, type_desc FROM sys.database_principals
WHERE name IN ('DBA', 'Bank_Manager', 'Bank_Officer', 'Customer');
-- Expected: 4 rows returned, all type_desc = 'DATABASE_ROLE'

-- TEST CASE 2: Confirm each test login is in the right role
SELECT r.name AS RoleName, m.name AS MemberName
FROM sys.database_role_members drm
JOIN sys.database_principals r ON drm.role_principal_id = r.principal_id
JOIN sys.database_principals m ON drm.member_principal_id = m.principal_id
WHERE m.name LIKE 'test_%';
-- Expected: 4 rows, each test user matched to its correct role

-- TEST CASE 3: DBA can create a table (positive -- schema rights work)
EXECUTE AS USER = 'test_dba_user';
CREATE TABLE dbo.DbaTestTable (ID INT);
DROP TABLE dbo.DbaTestTable;  -- clean up immediately after proving it works
REVERT;
-- Expected: both statements succeed with no permission errors

-- TEST CASE 3b: DBA is BLOCKED from disabling temporal versioning
-- on the 4 tables that support recovery and audit -- negative.
-- This is the specific risk the trigger above exists to close: if
-- this succeeded, a DBA could turn off versioning, silently lose
-- the entire audit/recovery guarantee for that table, tamper with
-- or delete data, then turn versioning back on with no trace.
EXECUTE AS USER = 'test_dba_user';
ALTER TABLE dbo.Staff SET (SYSTEM_VERSIONING = OFF);
REVERT;
-- Expected: the custom RAISERROR from trg_PreventVersioningDisable
-- fires and the statement is rolled back -- versioning stays ON

-- TEST CASE 3c: DBA CAN still ADD columns to these SAME 4 tables --
-- proves the trigger is scoped to two specific dangerous patterns,
-- not a blanket loss of Requirement 1's rights on the tables that
-- matter most
EXECUTE AS USER = 'test_dba_user';
ALTER TABLE dbo.Staff ADD TestColumn NVARCHAR(10) NULL;
REVERT;
-- Expected: succeeds with no error -- ADD COLUMN isn't one of the
-- two blocked patterns

-- TEST CASE 3d: DROP COLUMN specifically IS blocked -- negative.
-- Also demonstrates the documented emergency-override path while
-- cleaning up TestColumn from 3c, since normal DROP COLUMN can no
-- longer do it.
EXECUTE AS USER = 'test_dba_user';
ALTER TABLE dbo.Staff DROP COLUMN TestColumn;
REVERT;
-- Expected: blocked by the trigger -- TestColumn still exists

-- Cleanup, run as the sysadmin session (not test_dba_user --
-- disabling a database trigger requires rights DBA was never
-- given): the documented emergency override actually works
DISABLE TRIGGER trg_PreventVersioningDisable ON DATABASE;
ALTER TABLE dbo.Staff DROP COLUMN TestColumn;
ENABLE TRIGGER trg_PreventVersioningDisable ON DATABASE;
-- Expected: succeeds -- TestColumn is gone, trigger re-enabled and
-- protecting again

-- TEST CASE 4: DBA is BLOCKED from reading business data (negative)
EXECUTE AS USER = 'test_dba_user';
SELECT * FROM dbo.Customer;
REVERT;
-- Expected: "The SELECT permission was denied..." error

-- TEST CASE 5: Bank Officer is BLOCKED from direct table access (negative)
EXECUTE AS USER = 'test_officer_user';
SELECT * FROM dbo.Account;
REVERT;
-- Expected: permission denied error (Officer will only see Account
-- data later, through a view built in Task #4)

-- TEST CASE 6: Customer cannot create a table (negative -- proves
-- DDL rights are DBA-only, not just "not denied" for others)
EXECUTE AS USER = 'test_customer_user';
CREATE TABLE dbo.ShouldFail (ID INT);
REVERT;
-- Expected: "CREATE TABLE permission denied..." error

-- TEST CASE 7: Bank Manager is BLOCKED from direct table access (negative)
-- Run REVERT first the run the block below
REVERT;

EXECUTE AS USER = 'test_manager_user';
SELECT * FROM dbo.Staff;
REVERT;
-- Expected: permission denied error

-- ################################################################
-- TASK #6 TEST CASES -- for Task #4 (Views)
-- Grouped to match the build groups above -- test each group
-- right after building it, not all 14 at the very end.
-- ================================================================

-- ---------- GROUP A TESTS ----------

-- TEST 1: Everyone can see the staff directory (positive)
EXECUTE AS USER = 'test_customer_user';
SELECT * FROM dbo.vw_StaffDirectory;
REVERT;
-- Expected: succeeds, shows only StaffName + Phone columns

-- TEST 2: Customer is BLOCKED from vw_StaffOwnRecord (negative)
EXECUTE AS USER = 'test_customer_user';
SELECT * FROM dbo.vw_StaffOwnRecord;
REVERT;
-- Expected: permission denied error

-- TEST 3: Manager can see all Bank Officers (positive)
EXECUTE AS USER = 'test_manager_user';
SELECT * FROM dbo.vw_AllBankOfficers;
REVERT;
-- Expected: succeeds, shows only rows with Position = 'Bank Officer'

-- TEST 4: Customer is BLOCKED from vw_AllBankOfficers (negative)
EXECUTE AS USER = 'test_customer_user';
SELECT * FROM dbo.vw_AllBankOfficers;
REVERT;
-- Expected: permission denied error

-- ---------- GROUP B TESTS ----------

-- TEST 5: Officer can see all customers (positive)
EXECUTE AS USER = 'test_officer_user';
SELECT * FROM dbo.vw_CustomerAll;
REVERT;
-- Expected: succeeds, all customer rows returned

-- TEST 6: Customer is BLOCKED from vw_CustomerAll (negative)
EXECUTE AS USER = 'test_customer_user';
SELECT * FROM dbo.vw_CustomerAll;
REVERT;
-- Expected: permission denied error

-- TEST 7: Customer CAN query vw_AccountOwn, but sees ALL rows for
-- now -- this is EXPECTED, not a bug (RLS filtering is Task #5)
EXECUTE AS USER = 'test_customer_user';
SELECT * FROM dbo.vw_AccountOwn;
REVERT;
-- Expected: succeeds, but returns every account, not just one
-- customer's own -- flag this clearly as "pending Task #5" in
-- your report, not as a passed/failed test in the normal sense

-- ---------- GROUP C TESTS ----------

-- TEST 8: Manager can see all transactions (positive)
EXECUTE AS USER = 'test_manager_user';
SELECT * FROM dbo.vw_TransactionAll;
REVERT;
-- Expected: succeeds

-- TEST 9: Officer is BLOCKED from vw_TransactionOwn (negative --
-- this view is Customer-only)
EXECUTE AS USER = 'test_officer_user';
SELECT * FROM dbo.vw_TransactionOwn;
REVERT;
-- Expected: permission denied error

-- ---------- GROUP D TESTS ----------

-- TEST 10: Manager can see pending approvals (positive)
EXECUTE AS USER = 'test_manager_user';
SELECT * FROM dbo.vw_PendingApprovalAll;
REVERT;
-- Expected: succeeds

-- TEST 11: Officer is BLOCKED from vw_PendingApprovalAll (negative
-- -- Manager only)
EXECUTE AS USER = 'test_officer_user';
SELECT * FROM dbo.vw_PendingApprovalAll;
REVERT;
-- Expected: permission denied error

-- ---------- GROUP E TESTS ----------

-- TEST 12: DBA can read AuditLog (positive)
EXECUTE AS USER = 'test_dba_user';
SELECT * FROM AuditSchema.AuditLog;
REVERT;
-- Expected: succeeds

-- TEST 13: Officer is BLOCKED from AuditLog (negative)
EXECUTE AS USER = 'test_officer_user';
SELECT * FROM AuditSchema.AuditLog;
REVERT;
-- Expected: permission denied error

-- TEST 14: DBA can read Staff history (positive -- via nested
-- RecoveryAdmin membership, see Task #3)
EXECUTE AS USER = 'test_dba_user';
SELECT * FROM dbo.vw_Staff_History;
REVERT;
-- Expected: succeeds, shows current + historical rows

-- TEST 15: Manager is BLOCKED from Staff history (negative --
-- history is RecoveryAdmin-only, and Manager isn't a member of it)
EXECUTE AS USER = 'test_manager_user';
SELECT * FROM dbo.vw_Staff_History;
REVERT;
-- Expected: permission denied error

-- ################################################################
-- TASK #6 TEST CASES -- for Task #5 (Row-Level Security)
-- ================================================================

-- Set a known test password for the staff login
DECLARE @SSalt VARBINARY(32) = CRYPT_GEN_RANDOM(32);
UPDATE dbo.UserLogin
SET Salt = @SSalt,
    PasswordHash = HASHBYTES('SHA2_512', @SSalt + CONVERT(VARBINARY(4000), N'Test1234!')),
    PasswordLastChanged = SYSDATETIME(), FailedLoginAttempts = 0, LockoutUntil = NULL
WHERE Username = 'staff_hafizzainal';

-- Set a known test password for CUSTOMER A
DECLARE @CASalt VARBINARY(32) = CRYPT_GEN_RANDOM(32);
UPDATE dbo.UserLogin
SET Salt = @CASalt,
    PasswordHash = HASHBYTES('SHA2_512', @CASalt + CONVERT(VARBINARY(4000), N'Test1234!')),
    PasswordLastChanged = SYSDATETIME(), FailedLoginAttempts = 0, LockoutUntil = NULL
WHERE Username = 'cust_aimanhaziq';

-- Set a known test password for CUSTOMER B (a DIFFERENT customer)
DECLARE @CBSalt VARBINARY(32) = CRYPT_GEN_RANDOM(32);
UPDATE dbo.UserLogin
SET Salt = @CBSalt,
    PasswordHash = HASHBYTES('SHA2_512', @CBSalt + CONVERT(VARBINARY(4000), N'Test1234!')),
    PasswordLastChanged = SYSDATETIME(), FailedLoginAttempts = 0, LockoutUntil = NULL
WHERE Username = 'cust_gracelim';
GO

-- ---------- TEST 1: Staff sees ONLY their own record ----------
EXECUTE AS USER = 'test_officer_user';
DECLARE @Success BIT, @Expired BIT, @Msg NVARCHAR(200);
EXEC sp_Login 'staff_hafizzainal', 'Test1234!', @Success OUTPUT, @Expired OUTPUT, @Msg OUTPUT;
SELECT @Success AS LoginSuccess;
SELECT * FROM dbo.vw_StaffOwnRecord;
REVERT;
-- Expected: LoginSuccess = 1, exactly ONE row, StaffID = 7

-- ---------- TEST 2: Customer A sees ONLY their own accounts ----------
EXECUTE AS USER = 'test_customer_user';
DECLARE @Success2 BIT, @Expired2 BIT, @Msg2 NVARCHAR(200);
EXEC sp_Login 'cust_aimanhaziq', 'Test1234!', @Success2 OUTPUT, @Expired2 OUTPUT, @Msg2 OUTPUT;
SELECT * FROM dbo.vw_AccountOwn;
REVERT;
-- Expected: only rows where CustomerID = 2 -- note the AccountIDs,
-- you'll need them for Test 4

-- ---------- TEST 3: Customer A sees ONLY their own transactions ----------
EXECUTE AS USER = 'test_customer_user';
DECLARE @Success3 BIT, @Expired3 BIT, @Msg3 NVARCHAR(200);
EXEC sp_Login 'cust_aimanhaziq', 'Test1234!', @Success3 OUTPUT, @Expired3 OUTPUT, @Msg3 OUTPUT;
SELECT * FROM dbo.vw_TransactionOwn;
REVERT;
-- Expected: only transactions tied to CustomerID = 2's accounts

-- ---------- TEST 4: Cross-customer isolation (the real proof) ----------
EXECUTE AS USER = 'test_customer_user';
DECLARE @Success4 BIT, @Expired4 BIT, @Msg4 NVARCHAR(200);
EXEC sp_Login 'cust_gracelim', 'Test1234!', @Success4 OUTPUT, @Expired4 OUTPUT, @Msg4 OUTPUT;
SELECT * FROM dbo.vw_AccountOwn;
REVERT;
-- Expected: CustomerID = 3's own accounts ONLY -- Customer A's
-- (CustomerID 2) AccountIDs from Test 2 must NOT appear here

-- ---------- TEST 5: Fail-closed -- no login at all ----------
-- Run this in a BRAND NEW query window (not this tab)
USE SmartBankDB;
EXECUTE AS USER = 'test_customer_user';
SELECT * FROM dbo.vw_AccountOwn;
REVERT;
-- Expected: ZERO rows

-- ---------- TEST 6: Pending approvals filtered correctly ----------
EXECUTE AS USER = 'test_customer_user';
DECLARE @Success6 BIT, @Expired6 BIT, @Msg6 NVARCHAR(200);
EXEC sp_Login 'cust_aimanhaziq', 'Test1234!', @Success6 OUTPUT, @Expired6 OUTPUT, @Msg6 OUTPUT;
SELECT * FROM dbo.vw_PendingApprovalOwn;
REVERT;
-- Expected: only pending requests tied to CustomerID = 2's
-- accounts (may be zero if this customer has none pending --
-- recall Task #4 Test #10 showed a pending request tied to
-- AccountID 15; check which customer owns that account if you
-- want a guaranteed non-empty result here)

-- ################################################################
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
 

-- ################################################################
-- TASK: sp_DecryptOwnICNumber TEST CASES
-- ================================================================

-- TEST 1: Customer decrypts their OWN IC number -- positive
EXECUTE AS USER = 'test_customer_user';
DECLARE @L1 BIT, @E1 BIT, @M1 NVARCHAR(200);
EXEC sp_Login 'cust_aimanhaziq', 'Test1234!', @L1 OUTPUT, @E1 OUTPUT, @M1 OUTPUT;

EXEC dbo.sp_DecryptOwnICNumber;
REVERT;
-- Expected: one row, CustomerID = 2, ICNumber_Decrypted shows
-- Aiman's real 12-digit IC number, decrypted automatically

-- TEST 2: calling this without ever logging in first -- negative
EXECUTE AS USER = 'test_customer_user';
EXEC dbo.sp_DecryptOwnICNumber;
REVERT;
-- Expected: "You must be logged in as a customer to use this."
-- error -- MUST be run in a brand new query window, same
-- SESSION_CONTEXT-persists caveat as every other self-scoped proc

-- TEST 3: Bank Officer attempts to call this at all -- negative,
-- blocked at Layer 1 (this is Customer-only; Officer already has
-- sp_DecryptICNumber for decrypting ANY customer's IC as part of
-- their job -- this proc is specifically the self-service path)
EXECUTE AS USER = 'test_officer_user';
EXEC dbo.sp_DecryptOwnICNumber;
REVERT;
-- Expected: "EXECUTE permission was denied" error

PRINT 'sp_DecryptOwnICNumber test suite complete.';
GO


/* ================================================================
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
 

-- ################################################################
-- TASK #7 TEST CASES -- DML Audit Triggers
-- ================================================================

-- TEST 1: INSERT gets logged
INSERT INTO dbo.Staff (StaffName, Position, Branch, Phone, Salary, IsActive)
VALUES ('Trigger Test Staff', 'Bank Officer', 'Kuala Lumpur', '0100000000', 4500.00, 1);

SELECT TOP 1 * FROM AuditSchema.AuditLog WHERE TableName = 'Staff' AND ActionType = 'INSERT' ORDER BY LogID DESC;
-- Expected: one row, Activity shows the full new record, RecordID = new StaffID

-- TEST 2: UPDATE gets logged per changed column
UPDATE dbo.Staff SET Phone = '0199999999' WHERE StaffName = 'Trigger Test Staff';

SELECT * FROM AuditSchema.AuditLog WHERE TableName = 'Staff' AND ActionType = 'UPDATE' ORDER BY LogID DESC;
-- Expected: exactly one row, ColumnName = 'Phone', Activity = '<old number> -> 0199999999'

-- TEST 3: multi-column UPDATE logs one row per changed column
UPDATE dbo.Staff SET Branch = 'Subang', Salary = 5000.00 WHERE StaffName = 'Trigger Test Staff';

SELECT * FROM AuditSchema.AuditLog WHERE TableName = 'Staff' AND ActionType = 'UPDATE' ORDER BY LogID DESC;
-- Expected: TWO new rows -- one for Branch, one for Salary -- not one combined row

-- TEST 4: DELETE gets logged
DELETE FROM dbo.Staff WHERE StaffName = 'Trigger Test Staff';

SELECT TOP 1 * FROM AuditSchema.AuditLog WHERE TableName = 'Staff' AND ActionType = 'DELETE' ORDER BY LogID DESC;
-- Expected: one row, Activity shows the full deleted record

-- TEST 5: same coverage on Customer, confirming ICNumber is never
-- exposed in plaintext even though it changed
UPDATE dbo.Customer SET Phone = '0100001111' WHERE CustomerID = 2;

SELECT * FROM AuditSchema.AuditLog WHERE TableName = 'Customer' AND RecordID = '2' ORDER BY LogID DESC;
-- Expected: one row, ColumnName = 'Phone' -- no ICNumber row here since
-- ICNumber itself wasn't touched by this UPDATE

-- TEST 6: password change on UserLogin gets logged with the hash
-- placeholder, never the real bytes
UPDATE dbo.UserLogin
SET PasswordHash = HASHBYTES('SHA2_512', CRYPT_GEN_RANDOM(32) + CONVERT(VARBINARY(4000), N'Test1234!')),
    Salt = CRYPT_GEN_RANDOM(32)
WHERE Username = 'staff_hafizzainal';

SELECT * FROM AuditSchema.AuditLog WHERE TableName = 'UserLogin' ORDER BY LogID DESC;
-- Expected: TWO rows (PasswordHash, Salt), both showing Activity =
-- '<hash changed>' -- never real bytes

-- TEST 7: deactivating a UserLogin gets logged as a combined transition
UPDATE dbo.UserLogin SET IsActive = 0 WHERE Username = 'staff_hafizzainal';

SELECT TOP 1 * FROM AuditSchema.AuditLog WHERE TableName = 'UserLogin' AND ColumnName = 'IsActive' ORDER BY LogID DESC;
-- Expected: one row, Activity = 'Active -> Inactive'

-- Cleanup: reactivate the test account so it doesn't interfere with
-- earlier login/RLS tests if this script is re-run top to bottom
UPDATE dbo.UserLogin SET IsActive = 1 WHERE Username = 'staff_hafizzainal';

-- TEST 8: changing a security policy value gets logged
UPDATE dbo.SecurityConfig SET ConfigValue = 5 WHERE ConfigKey = 'MaxFailedAttempts';

SELECT * FROM AuditSchema.AuditLog WHERE TableName = 'SecurityConfig' ORDER BY LogID DESC;
-- Expected: one row, RecordID = 'MaxFailedAttempts', Activity = '3 -> 5'

-- Cleanup: restore the original policy value
UPDATE dbo.SecurityConfig SET ConfigValue = 3 WHERE ConfigKey = 'MaxFailedAttempts';

PRINT 'Part 7 (DML Audit Triggers) test suite complete.';


-- ################################################################
-- TASK #8 TEST CASES -- sp_ManageStaff
-- test_manager_user / test_officer_user / test_customer_user were
-- all dropped at the end of Part 6's cleanup -- recreated here
-- since Part 8's tests (sp_ManageStaff, sp_ManageCustomer,
-- sp_ManageAccount) need all three again.
-- ================================================================
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


-- TEST 1: Manager creates a new Bank Officer -- positive
EXECUTE AS USER = 'test_manager_user';
DECLARE @Success BIT, @Msg NVARCHAR(200);
EXEC dbo.sp_ManageStaff
    @StaffID = NULL, @StaffName = 'Test Officer One', @Position = 'Bank Officer',
    @Branch = 'Kuala Lumpur', @Phone = '0161234567', @Salary = 4500.00, @IsActive = 1,
    @Success = @Success OUTPUT, @Message = @Msg OUTPUT;
SELECT @Success AS Success, @Msg AS Message;
REVERT;
-- Expected: Success = 1, Message = 'Staff record created successfully.'

-- TEST 2: confirm the audit trigger caught it automatically, no
-- extra code in the proc needed for this
SELECT TOP 1 * FROM AuditSchema.AuditLog WHERE TableName = 'Staff' AND ActionType = 'INSERT' ORDER BY LogID DESC;
-- Expected: one row, ChangedBy shows 'test_manager_user' with no
-- role resolved in parentheses (this test session has no
-- SESSION_CONTEXT set via sp_Login, so fn_GetSessionUsername falls
-- back to the raw SQL login name)

-- TEST 3: Manager updates that officer's Phone and Salary -- positive
DECLARE @NewStaffID INT = (SELECT StaffID FROM dbo.Staff WHERE StaffName = 'Test Officer One');

EXECUTE AS USER = 'test_manager_user';
DECLARE @Success3 BIT, @Msg3 NVARCHAR(200);
EXEC dbo.sp_ManageStaff
    @StaffID = @NewStaffID, @StaffName = 'Test Officer One', @Position = 'Bank Officer',
    @Branch = 'Kuala Lumpur', @Phone = '0169999999', @Salary = 4800.00, @IsActive = 1,
    @Success = @Success3 OUTPUT, @Message = @Msg3 OUTPUT;
SELECT @Success3 AS Success, @Msg3 AS Message;
REVERT;
-- Expected: Success = 1

SELECT * FROM AuditSchema.AuditLog WHERE TableName = 'Staff' AND RecordID = CONVERT(NVARCHAR(50), @NewStaffID) AND ActionType = 'UPDATE' ORDER BY LogID DESC;
-- Expected: TWO rows -- one for Phone, one for Salary -- each
-- showing "old -> new" in Activity

-- TEST 4: Manager tries to create a Bank Manager via this proc -- negative
EXECUTE AS USER = 'test_manager_user';
DECLARE @Success4 BIT, @Msg4 NVARCHAR(200);
EXEC dbo.sp_ManageStaff
    @StaffID = NULL, @StaffName = 'Should Fail', @Position = 'Bank Manager',
    @Branch = 'Klang', @Phone = '0161111111', @Salary = 8000.00, @IsActive = 1,
    @Success = @Success4 OUTPUT, @Message = @Msg4 OUTPUT;
SELECT @Success4 AS Success, @Msg4 AS Message;
REVERT;
-- Expected: Success = 0, 'sp_ManageStaff can only create or update Bank Officer records.'

-- TEST 5: Manager tries to update an actual Bank Manager's record -- negative
EXECUTE AS USER = 'test_manager_user';
DECLARE @Success5 BIT, @Msg5 NVARCHAR(200);
EXEC dbo.sp_ManageStaff
    @StaffID = 2, @StaffName = 'Farid Osman', @Position = 'Bank Officer',
    @Branch = 'Kuala Lumpur', @Phone = '0122345678', @Salary = 8200.00, @IsActive = 1,
    @Success = @Success5 OUTPUT, @Message = @Msg5 OUTPUT;
SELECT @Success5 AS Success, @Msg5 AS Message;
REVERT;
-- Expected: Success = 0, 'This staff record is not a Bank Officer and is outside sp_ManageStaff''s scope.'
-- (StaffID 2 = Farid Osman, a Bank Manager -- confirms the scope
-- check works even though the CALLER passed a valid @Position)

-- TEST 6: Bank Officer attempts to call this proc at all -- negative,
-- blocked at Layer 1 before Layer 2 logic even runs
EXECUTE AS USER = 'test_officer_user';
DECLARE @Success6 BIT, @Msg6 NVARCHAR(200);
EXEC dbo.sp_ManageStaff
    @StaffID = NULL, @StaffName = 'Should Also Fail', @Position = 'Bank Officer',
    @Branch = 'Subang', @Phone = '0162222222', @Salary = 4500.00, @IsActive = 1,
    @Success = @Success6 OUTPUT, @Message = @Msg6 OUTPUT;
REVERT;
-- Expected: "EXECUTE permission was denied" error -- SQL Server
-- blocks this before the proc body ever runs

-- TEST 7: confirm all REJECTED attempts got logged
SELECT * FROM AuditSchema.AuditLog WHERE TableName = 'Staff' AND ActionType = 'REJECTED' ORDER BY LogID DESC;
-- Expected: two rows -- TEST 4 and TEST 5's rejections (TEST 6
-- never reached the proc body, so it has no REJECTED row -- SQL
-- Server's own permission error is the record of that attempt)

-- Cleanup: remove the test officer record
DELETE FROM dbo.Staff WHERE StaffName = 'Test Officer One';

PRINT 'Part 8 (sp_ManageStaff) test suite complete.';
GO


-- ================================================================
-- TASK #8b TEST CASES -- sp_ManageCustomer
-- (test_officer_user / test_manager_user already exist from the
-- sp_ManageStaff test setup above -- no need to recreate them)
-- ================================================================

-- TEST 1: Officer creates a new customer -- positive, exercises
-- the real CLE encryption path for the first time in the system
EXECUTE AS USER = 'test_officer_user';
DECLARE @Success BIT, @Msg NVARCHAR(200);
EXEC dbo.sp_ManageCustomer
    @CustomerID = NULL, @CustomerName = 'Test Customer One', @ICNumber = '950101105678',
    @Phone = '0171234567', @Address = 'No 99, Jalan Test, Kuala Lumpur', @IsActive = 1,
    @Success = @Success OUTPUT, @Message = @Msg OUTPUT;
SELECT @Success AS Success, @Msg AS Message;
REVERT;
-- Expected: Success = 1

-- TEST 2: confirm the audit trigger caught the INSERT automatically
SELECT TOP 1 * FROM AuditSchema.AuditLog WHERE TableName = 'Customer' AND ActionType = 'INSERT' ORDER BY LogID DESC;
-- Expected: one row, Activity shows the new record summary,
-- ICNumber shown as '<encrypted>' -- never the plaintext IC

-- TEST 3: confirm the real CLE round-trip actually works -- decrypt
-- the customer just created and check it matches what was typed in
DECLARE @NewCustomerID INT = (SELECT CustomerID FROM dbo.Customer WHERE CustomerName = 'Test Customer One');

EXECUTE AS USER = 'test_officer_user';
EXEC dbo.sp_DecryptICNumber @CustomerID = @NewCustomerID;
REVERT;
-- Expected: succeeds, ICNumber_Decrypted = '950101105678' -- proves
-- the real symmetric key encrypted it correctly, not a placeholder

-- TEST 4: Officer updates that customer's Phone -- positive
EXECUTE AS USER = 'test_officer_user';
DECLARE @Success4 BIT, @Msg4 NVARCHAR(200);
EXEC dbo.sp_ManageCustomer
    @CustomerID = @NewCustomerID, @CustomerName = 'Test Customer One', @ICNumber = NULL,
    @Phone = '0179999999', @Address = 'No 99, Jalan Test, Kuala Lumpur', @IsActive = 1,
    @Success = @Success4 OUTPUT, @Message = @Msg4 OUTPUT;
SELECT @Success4 AS Success, @Msg4 AS Message;
REVERT;
-- Expected: Success = 1

SELECT * FROM AuditSchema.AuditLog WHERE TableName = 'Customer' AND RecordID = CONVERT(NVARCHAR(50), @NewCustomerID) AND ActionType = 'UPDATE' ORDER BY LogID DESC;
-- Expected: one row, ColumnName = 'Phone' -- no ICNumber row, since
-- this proc never touches it on the UPDATE path

-- TEST 5: duplicate IC number gets rejected -- negative
EXECUTE AS USER = 'test_officer_user';
DECLARE @Success5 BIT, @Msg5 NVARCHAR(200);
EXEC dbo.sp_ManageCustomer
    @CustomerID = NULL, @CustomerName = 'Should Fail Duplicate', @ICNumber = '950101105678',
    @Phone = '0171111111', @Address = 'Somewhere', @IsActive = 1,
    @Success = @Success5 OUTPUT, @Message = @Msg5 OUTPUT;
SELECT @Success5 AS Success, @Msg5 AS Message;
REVERT;
-- Expected: Success = 0, 'A customer record already exists for that IC number.'

-- TEST 6: malformed IC number gets rejected -- negative
EXECUTE AS USER = 'test_officer_user';
DECLARE @Success6 BIT, @Msg6 NVARCHAR(200);
EXEC dbo.sp_ManageCustomer
    @CustomerID = NULL, @CustomerName = 'Should Also Fail', @ICNumber = '12345',
    @Phone = '0172222222', @Address = 'Somewhere', @IsActive = 1,
    @Success = @Success6 OUTPUT, @Message = @Msg6 OUTPUT;
SELECT @Success6 AS Success, @Msg6 AS Message;
REVERT;
-- Expected: Success = 0, 'ICNumber is required and must be exactly 12 digits.'

-- TEST 7: Bank Manager attempts to call this proc at all -- negative,
-- blocked at Layer 1 (this is Officer territory, not Manager's)
EXECUTE AS USER = 'test_manager_user';
DECLARE @Success7 BIT, @Msg7 NVARCHAR(200);
EXEC dbo.sp_ManageCustomer
    @CustomerID = NULL, @CustomerName = 'Should Fail Role', @ICNumber = '950101109999',
    @Phone = '0173333333', @Address = 'Somewhere', @IsActive = 1,
    @Success = @Success7 OUTPUT, @Message = @Msg7 OUTPUT;
REVERT;
-- Expected: "EXECUTE permission was denied" error

-- Cleanup: remove the test customer record
DELETE FROM dbo.Customer WHERE CustomerName = 'Test Customer One';

PRINT 'Part 8b (sp_ManageCustomer) test suite complete.';
GO


-- ================================================================
-- TASK #8c TEST CASES -- sp_ManageAccount
-- ================================================================

-- TEST 1: Officer opens a new account for an existing active
-- customer -- positive, confirms it starts at RM0.00
EXECUTE AS USER = 'test_officer_user';
DECLARE @Success BIT, @Msg NVARCHAR(200);
EXEC dbo.sp_ManageAccount
    @AccountID = NULL, @CustomerID = 2, @AccountType = 'Savings', @IsActive = 1,
    @Success = @Success OUTPUT, @Message = @Msg OUTPUT;
SELECT @Success AS Success, @Msg AS Message;
REVERT;
-- Expected: Success = 1

DECLARE @NewAccountID INT = (SELECT TOP 1 AccountID FROM dbo.Account WHERE CustomerID = 2 ORDER BY AccountID DESC);
SELECT AccountID, Balance FROM dbo.Account WHERE AccountID = @NewAccountID;
-- Expected: Balance = 0.00

-- TEST 2: confirm the audit trigger caught it automatically
SELECT TOP 1 * FROM AuditSchema.AuditLog WHERE TableName = 'Account' AND ActionType = 'INSERT' ORDER BY LogID DESC;
-- Expected: one row, Activity shows the new record summary including Balance=0.00

-- TEST 3: Officer updates that account's type -- positive
EXECUTE AS USER = 'test_officer_user';
DECLARE @Success3 BIT, @Msg3 NVARCHAR(200);
EXEC dbo.sp_ManageAccount
    @AccountID = @NewAccountID, @CustomerID = NULL, @AccountType = 'Current', @IsActive = 1,
    @Success = @Success3 OUTPUT, @Message = @Msg3 OUTPUT;
SELECT @Success3 AS Success, @Msg3 AS Message;
REVERT;
-- Expected: Success = 1

SELECT * FROM AuditSchema.AuditLog WHERE TableName = 'Account' AND RecordID = CONVERT(NVARCHAR(50), @NewAccountID) AND ActionType = 'UPDATE' ORDER BY LogID DESC;
-- Expected: one row, ColumnName = 'AccountType', Activity = 'Savings -> Current'

-- TEST 4: attempting to close an account with money in it gets
-- rejected -- negative. AccountID 2 (Aiman's Savings) has a real
-- seeded balance.
EXECUTE AS USER = 'test_officer_user';
DECLARE @Success4 BIT, @Msg4 NVARCHAR(200);
EXEC dbo.sp_ManageAccount
    @AccountID = 2, @CustomerID = NULL, @AccountType = 'Savings', @IsActive = 0,
    @Success = @Success4 OUTPUT, @Message = @Msg4 OUTPUT;
SELECT @Success4 AS Success, @Msg4 AS Message;
REVERT;
-- Expected: Success = 0, 'Cannot close an account with a non-zero balance...'

-- TEST 5: opening an account for an INACTIVE customer gets
-- rejected -- negative. CustomerID 1 is the seeded inactive customer.
EXECUTE AS USER = 'test_officer_user';
DECLARE @Success5 BIT, @Msg5 NVARCHAR(200);
EXEC dbo.sp_ManageAccount
    @AccountID = NULL, @CustomerID = 1, @AccountType = 'Savings', @IsActive = 1,
    @Success = @Success5 OUTPUT, @Message = @Msg5 OUTPUT;
SELECT @Success5 AS Success, @Msg5 AS Message;
REVERT;
-- Expected: Success = 0, 'Cannot open an account for an inactive customer.'

-- TEST 6: invalid AccountType gets rejected -- negative
EXECUTE AS USER = 'test_officer_user';
DECLARE @Success6 BIT, @Msg6 NVARCHAR(200);
EXEC dbo.sp_ManageAccount
    @AccountID = NULL, @CustomerID = 2, @AccountType = 'Crypto Wallet', @IsActive = 1,
    @Success = @Success6 OUTPUT, @Message = @Msg6 OUTPUT;
SELECT @Success6 AS Success, @Msg6 AS Message;
REVERT;
-- Expected: Success = 0, 'AccountType must be Savings, Current, or Fixed Deposit.'

-- TEST 7: Customer attempts to call this proc at all -- negative,
-- blocked at Layer 1
EXECUTE AS USER = 'test_customer_user';
DECLARE @Success7 BIT, @Msg7 NVARCHAR(200);
EXEC dbo.sp_ManageAccount
    @AccountID = NULL, @CustomerID = 2, @AccountType = 'Savings', @IsActive = 1,
    @Success = @Success7 OUTPUT, @Message = @Msg7 OUTPUT;
REVERT;
-- Expected: "EXECUTE permission was denied" error

-- Cleanup: remove the test account
DELETE FROM dbo.Account WHERE AccountID = @NewAccountID;

PRINT 'Part 8c (sp_ManageAccount) test suite complete.';
GO


-- ================================================================
-- TASK #8d TEST CASES -- sp_UpdateOwnStaffRecord
-- ================================================================

-- Setup: staff_aisharahman (DBA) has never had a test password set
-- anywhere in this file -- set one now
DECLARE @DbaSalt VARBINARY(32) = CRYPT_GEN_RANDOM(32);
UPDATE dbo.UserLogin
SET Salt = @DbaSalt,
    PasswordHash = HASHBYTES('SHA2_512', @DbaSalt + CONVERT(VARBINARY(4000), N'Test1234!')),
    PasswordLastChanged = SYSDATETIME(), FailedLoginAttempts = 0, LockoutUntil = NULL
WHERE Username = 'staff_aisharahman';
GO

-- TEST 1: Officer updates their own phone number -- positive
EXECUTE AS USER = 'test_officer_user';
DECLARE @L1 BIT, @E1 BIT, @M1 NVARCHAR(200);
EXEC sp_Login 'staff_hafizzainal', 'Test1234!', @L1 OUTPUT, @E1 OUTPUT, @M1 OUTPUT;

DECLARE @Success BIT, @Msg NVARCHAR(200);
EXEC dbo.sp_UpdateOwnStaffRecord @Phone = '0161239999', @Success = @Success OUTPUT, @Message = @Msg OUTPUT;
SELECT @Success AS Success, @Msg AS Message;
REVERT;
-- Expected: Success = 1

-- TEST 2: confirm it only touched StaffID 7 (Hafiz), and the
-- trigger caught it automatically
SELECT * FROM AuditSchema.AuditLog WHERE TableName = 'Staff' AND RecordID = '7' AND ActionType = 'UPDATE' ORDER BY LogID DESC;
-- Expected: one row, ColumnName = 'Phone'

-- TEST 3: DBA updates their own phone number -- positive, proves
-- "each staff" genuinely includes DBA
EXECUTE AS USER = 'test_dba_user';
DECLARE @L3 BIT, @E3 BIT, @M3 NVARCHAR(200);
EXEC sp_Login 'staff_aisharahman', 'Test1234!', @L3 OUTPUT, @E3 OUTPUT, @M3 OUTPUT;

DECLARE @Success3 BIT, @Msg3 NVARCHAR(200);
EXEC dbo.sp_UpdateOwnStaffRecord @Phone = '0121239999', @Success = @Success3 OUTPUT, @Message = @Msg3 OUTPUT;
SELECT @Success3 AS Success, @Msg3 AS Message;
REVERT;
-- Expected: Success = 1

-- TEST 4: calling this without ever logging in first -- negative.
-- MUST be run in a BRAND NEW query window (not this one) -- same
-- caveat as Part 4's RLS fail-closed test: SESSION_CONTEXT persists
-- for the whole session, so running this right after TEST 1/3 in
-- the SAME window would still see Hafiz's or Aisha's leftover
-- login context from those earlier sp_Login calls, not a genuinely
-- empty one.
USE SmartBankDB;
EXECUTE AS USER = 'test_officer_user';
DECLARE @Success4 BIT, @Msg4 NVARCHAR(200);
EXEC dbo.sp_UpdateOwnStaffRecord @Phone = '0100000000', @Success = @Success4 OUTPUT, @Message = @Msg4 OUTPUT;
SELECT @Success4 AS Success, @Msg4 AS Message;
REVERT;
-- Expected: Success = 0, 'You must be logged in as a staff member to use this.'
-- -- test_officer_user DOES have EXECUTE permission (Layer 1
-- passes), which is exactly why this proves the internal
-- SESSION_CONTEXT check (Layer 2) on its own, separate from TEST 5

-- TEST 5: Customer role has no EXECUTE on this at all -- negative,
-- blocked at Layer 1 before Layer 2 logic ever runs
EXECUTE AS USER = 'test_customer_user';
DECLARE @Success5 BIT, @Msg5 NVARCHAR(200);
EXEC dbo.sp_UpdateOwnStaffRecord @Phone = '0100000001', @Success = @Success5 OUTPUT, @Message = @Msg5 OUTPUT;
REVERT;
-- Expected: "EXECUTE permission was denied" error

PRINT 'Part 8d (sp_UpdateOwnStaffRecord) test suite complete.';
GO


-- ================================================================
-- TASK #8e TEST CASES -- sp_ProcessTransaction
-- Uses AccountID 2/3/23 (Aiman, CustomerID 2) and AccountID 4
-- (Grace, CustomerID 3) -- ownership mapping confirmed against the
-- baseline seed data before writing these.
-- ================================================================

-- TEST 1: Aiman deposits into his own Savings account -- positive
EXECUTE AS USER = 'test_customer_user';
DECLARE @L1 BIT, @E1 BIT, @M1 NVARCHAR(200);
EXEC sp_Login 'cust_aimanhaziq', 'Test1234!', @L1 OUTPUT, @E1 OUTPUT, @M1 OUTPUT;

DECLARE @Success BIT, @Msg NVARCHAR(200);
EXEC dbo.sp_ProcessTransaction
    @AccountID = 2, @TransactionType = 'Deposit', @Amount = 500.00, @ToAccountID = NULL,
    @Success = @Success OUTPUT, @Message = @Msg OUTPUT;
SELECT @Success AS Success, @Msg AS Message;
SELECT Balance FROM dbo.Account WHERE AccountID = 2;
REVERT;
-- Expected: Success = 1, Balance now 3700.00 (was 3200.00)

-- TEST 2: confirm the trigger caught it automatically
SELECT TOP 1 * FROM AuditSchema.AuditLog WHERE TableName = 'Account' AND RecordID = '2' AND ActionType = 'UPDATE' ORDER BY LogID DESC;
-- Expected: one row, ColumnName = 'Balance', Activity = '3200.00 -> 3700.00'

-- TEST 3: Aiman withdraws from his own Current account -- positive
EXECUTE AS USER = 'test_customer_user';
DECLARE @L3 BIT, @E3 BIT, @M3 NVARCHAR(200);
EXEC sp_Login 'cust_aimanhaziq', 'Test1234!', @L3 OUTPUT, @E3 OUTPUT, @M3 OUTPUT;

DECLARE @Success3 BIT, @Msg3 NVARCHAR(200);
EXEC dbo.sp_ProcessTransaction
    @AccountID = 3, @TransactionType = 'Withdrawal', @Amount = 200.00, @ToAccountID = NULL,
    @Success = @Success3 OUTPUT, @Message = @Msg3 OUTPUT;
SELECT @Success3 AS Success, @Msg3 AS Message;
REVERT;
-- Expected: Success = 1

-- TEST 4: Aiman transfers between his OWN two accounts -- positive
EXECUTE AS USER = 'test_customer_user';
DECLARE @L4 BIT, @E4 BIT, @M4 NVARCHAR(200);
EXEC sp_Login 'cust_aimanhaziq', 'Test1234!', @L4 OUTPUT, @E4 OUTPUT, @M4 OUTPUT;

DECLARE @Success4 BIT, @Msg4 NVARCHAR(200);
EXEC dbo.sp_ProcessTransaction
    @AccountID = 2, @TransactionType = 'Transfer', @Amount = 300.00, @ToAccountID = 3,
    @Success = @Success4 OUTPUT, @Message = @Msg4 OUTPUT;
SELECT @Success4 AS Success, @Msg4 AS Message;
SELECT AccountID, Balance FROM dbo.Account WHERE AccountID IN (2, 3);
REVERT;
-- Expected: Success = 1, AccountID 2 down by 300, AccountID 3 up by 300

-- TEST 5: withdrawal exceeding balance gets rejected -- negative
EXECUTE AS USER = 'test_customer_user';
DECLARE @L5 BIT, @E5 BIT, @M5 NVARCHAR(200);
EXEC sp_Login 'cust_aimanhaziq', 'Test1234!', @L5 OUTPUT, @E5 OUTPUT, @M5 OUTPUT;

DECLARE @Success5 BIT, @Msg5 NVARCHAR(200);
EXEC dbo.sp_ProcessTransaction
    @AccountID = 3, @TransactionType = 'Withdrawal', @Amount = 999999.00, @ToAccountID = NULL,
    @Success = @Success5 OUTPUT, @Message = @Msg5 OUTPUT;
SELECT @Success5 AS Success, @Msg5 AS Message;
REVERT;
-- Expected: Success = 0, 'Insufficient balance for this transaction.'

-- TEST 6: Aiman tries to withdraw from Grace's account -- negative,
-- proves the ownership check on WRITES, not just reads
EXECUTE AS USER = 'test_customer_user';
DECLARE @L6 BIT, @E6 BIT, @M6 NVARCHAR(200);
EXEC sp_Login 'cust_aimanhaziq', 'Test1234!', @L6 OUTPUT, @E6 OUTPUT, @M6 OUTPUT;

DECLARE @Success6 BIT, @Msg6 NVARCHAR(200);
EXEC dbo.sp_ProcessTransaction
    @AccountID = 4, @TransactionType = 'Withdrawal', @Amount = 100.00, @ToAccountID = NULL,
    @Success = @Success6 OUTPUT, @Message = @Msg6 OUTPUT;
SELECT @Success6 AS Success, @Msg6 AS Message;
REVERT;
-- Expected: Success = 0, 'You can only perform transactions on your own accounts.'
-- -- AccountID 4 belongs to Grace (CustomerID 3), not Aiman

-- TEST 7: a large deposit routes to PendingApproval instead of
-- posting directly -- team's own extension, not spec-required
EXECUTE AS USER = 'test_customer_user';
DECLARE @L7 BIT, @E7 BIT, @M7 NVARCHAR(200);
EXEC sp_Login 'cust_aimanhaziq', 'Test1234!', @L7 OUTPUT, @E7 OUTPUT, @M7 OUTPUT;

DECLARE @Success7 BIT, @Msg7 NVARCHAR(200);
EXEC dbo.sp_ProcessTransaction
    @AccountID = 23, @TransactionType = 'Deposit', @Amount = 15000.00, @ToAccountID = NULL,
    @Success = @Success7 OUTPUT, @Message = @Msg7 OUTPUT;
SELECT @Success7 AS Success, @Msg7 AS Message;
REVERT;
-- Expected: Success = 1, 'Transaction exceeds RM10,000 and requires
-- Manager approval. Submitted for review.' -- Balance on AccountID
-- 23 should NOT have changed yet

SELECT * FROM dbo.PendingApproval WHERE AccountID = 23 ORDER BY RequestID DESC;
-- Expected: one new row, Status = 'Pending', RequestedBy = 'cust_aimanhaziq'

-- TEST 8: Bank Officer attempts to call this proc at all --
-- negative, blocked at Layer 1 (this is Customer-only territory)
EXECUTE AS USER = 'test_officer_user';
DECLARE @Success8 BIT, @Msg8 NVARCHAR(200);
EXEC dbo.sp_ProcessTransaction
    @AccountID = 2, @TransactionType = 'Deposit', @Amount = 50.00, @ToAccountID = NULL,
    @Success = @Success8 OUTPUT, @Message = @Msg8 OUTPUT;
REVERT;
-- Expected: "EXECUTE permission was denied" error

PRINT 'Part 8e (sp_ProcessTransaction) test suite complete.';
GO


-- ================================================================
-- TASK #8f TEST CASES -- sp_ApproveTransaction
-- ================================================================

-- Setup: staff_faridosman (Bank Manager) has never had a test
-- password set anywhere in this file -- set one now
DECLARE @MgrSalt VARBINARY(32) = CRYPT_GEN_RANDOM(32);
UPDATE dbo.UserLogin
SET Salt = @MgrSalt,
    PasswordHash = HASHBYTES('SHA2_512', @MgrSalt + CONVERT(VARBINARY(4000), N'Test1234!')),
    PasswordLastChanged = SYSDATETIME(), FailedLoginAttempts = 0, LockoutUntil = NULL
WHERE Username = 'staff_faridosman';
GO

-- TEST 1: approve a valid pending Deposit -- positive. Uses the
-- RM15,000 deposit request Part 8e's TEST 7 created on AccountID 23.
DECLARE @DepositRequestID INT = (SELECT TOP 1 RequestID FROM dbo.PendingApproval WHERE AccountID = 23 AND TransactionType = 'Deposit' ORDER BY RequestID DESC);
DECLARE @BalanceBefore DECIMAL(15,2) = (SELECT Balance FROM dbo.Account WHERE AccountID = 23);

EXECUTE AS USER = 'test_manager_user';
DECLARE @L1 BIT, @E1 BIT, @M1 NVARCHAR(200);
EXEC sp_Login 'staff_faridosman', 'Test1234!', @L1 OUTPUT, @E1 OUTPUT, @M1 OUTPUT;

DECLARE @Success BIT, @Msg NVARCHAR(200);
EXEC dbo.sp_ApproveTransaction @RequestID = @DepositRequestID, @Approve = 1, @Success = @Success OUTPUT, @Message = @Msg OUTPUT;
SELECT @Success AS Success, @Msg AS Message;
REVERT;
-- Expected: Success = 1

SELECT Balance FROM dbo.Account WHERE AccountID = 23;
-- Expected: Balance = @BalanceBefore + 15000.00

SELECT * FROM dbo.PendingApproval WHERE RequestID = @DepositRequestID;
-- Expected: Status = 'Approved', ApprovedBy = 'staff_faridosman'

-- TEST 2: confirm both the TransactionRecord INSERT and the
-- PendingApproval UPDATE got caught by their triggers automatically
SELECT TOP 1 * FROM AuditSchema.AuditLog WHERE TableName = 'TransactionRecord' ORDER BY LogID DESC;
SELECT * FROM AuditSchema.AuditLog WHERE TableName = 'PendingApproval' AND RecordID = CONVERT(NVARCHAR(50), @DepositRequestID) ORDER BY LogID DESC;
-- Expected: one INSERT row on TransactionRecord, and Status/
-- ApprovedBy/ApprovalDate UPDATE rows on PendingApproval

-- TEST 3: attempting to approve the ALREADY-approved request again
-- -- negative
EXECUTE AS USER = 'test_manager_user';
DECLARE @Success3 BIT, @Msg3 NVARCHAR(200);
EXEC dbo.sp_ApproveTransaction @RequestID = @DepositRequestID, @Approve = 1, @Success = @Success3 OUTPUT, @Message = @Msg3 OUTPUT;
SELECT @Success3 AS Success, @Msg3 AS Message;
REVERT;
-- Expected: Success = 0, 'This request has already been Approved...'

-- TEST 4: approving a request that no longer has sufficient funds
-- -- negative. Uses the ORIGINAL seeded pending row: a RM15,000
-- Withdrawal against AccountID 15, which only ever had RM3,600.00.
EXECUTE AS USER = 'test_manager_user';
DECLARE @Success4 BIT, @Msg4 NVARCHAR(200);
EXEC dbo.sp_ApproveTransaction @RequestID = 1, @Approve = 1, @Success = @Success4 OUTPUT, @Message = @Msg4 OUTPUT;
SELECT @Success4 AS Success, @Msg4 AS Message;
REVERT;
-- Expected: Success = 0, 'Cannot approve -- insufficient balance...'

SELECT Status FROM dbo.PendingApproval WHERE RequestID = 1;
-- Expected: still 'Pending' -- a failed approval attempt does NOT
-- auto-resolve the request one way or the other

-- TEST 5: reject a pending request -- positive. Submits a fresh
-- large transaction first so there's something to reject.
EXECUTE AS USER = 'test_customer_user';
DECLARE @L5 BIT, @E5 BIT, @M5 NVARCHAR(200);
EXEC sp_Login 'cust_gracelim', 'Test1234!', @L5 OUTPUT, @E5 OUTPUT, @M5 OUTPUT;

DECLARE @Success5a BIT, @Msg5a NVARCHAR(200);
EXEC dbo.sp_ProcessTransaction
    @AccountID = 5, @TransactionType = 'Deposit', @Amount = 12000.00, @ToAccountID = NULL,
    @Success = @Success5a OUTPUT, @Message = @Msg5a OUTPUT;
REVERT;

DECLARE @RejectRequestID INT = (SELECT TOP 1 RequestID FROM dbo.PendingApproval WHERE AccountID = 5 ORDER BY RequestID DESC);

EXECUTE AS USER = 'test_manager_user';
DECLARE @Success5 BIT, @Msg5 NVARCHAR(200);
EXEC dbo.sp_ApproveTransaction @RequestID = @RejectRequestID, @Approve = 0, @Success = @Success5 OUTPUT, @Message = @Msg5 OUTPUT;
SELECT @Success5 AS Success, @Msg5 AS Message;
REVERT;
-- Expected: Success = 1, 'Transaction request rejected.'

SELECT Status, Balance FROM dbo.PendingApproval p JOIN dbo.Account a ON p.AccountID = a.AccountID WHERE p.RequestID = @RejectRequestID;
-- Expected: Status = 'Rejected', Balance UNCHANGED -- rejection never touches money

-- TEST 6: Bank Officer attempts to call this proc at all --
-- negative, blocked at Layer 1 (Manager-only territory)
EXECUTE AS USER = 'test_officer_user';
DECLARE @Success6 BIT, @Msg6 NVARCHAR(200);
EXEC dbo.sp_ApproveTransaction @RequestID = 1, @Approve = 1, @Success = @Success6 OUTPUT, @Message = @Msg6 OUTPUT;
REVERT;
-- Expected: "EXECUTE permission was denied" error

PRINT 'Part 8f (sp_ApproveTransaction) test suite complete.';
GO


-- ################################################################
-- TASK #9 TEST CASES -- Recovery Procedures
-- Each table gets both scenarios tested: A) roll back a bad
-- UPDATE, B) restore a DELETEd row. For Scenario B, test rows are
-- inserted directly (bypassing sp_ManageStaff/sp_ManageCustomer,
-- which would also provision a UserLogin) so they have no FK
-- dependents and can actually be deleted cleanly to test recovery.
-- WAITFOR DELAY is used to make the temporal boundaries between
-- "before" and "after" states unambiguous.
-- ================================================================

-- ---------- sp_RecoverStaff: Scenario A (rollback a bad update) ----------
INSERT INTO dbo.Staff (StaffName, Position, Branch, Phone, Salary, IsActive)
VALUES ('Recovery Test Staff', 'Bank Officer', 'Kuala Lumpur', '0100000001', 4500.00, 1);
DECLARE @RecStaffID INT = SCOPE_IDENTITY();

WAITFOR DELAY '00:00:01';
DECLARE @GoodStaffTime DATETIME2 = SYSDATETIME();  -- correct state as of here
WAITFOR DELAY '00:00:01';

UPDATE dbo.Staff SET Salary = 999999.00 WHERE StaffID = @RecStaffID;  -- the "mistake"

EXECUTE AS USER = 'test_dba_user';
DECLARE @Success BIT, @Msg NVARCHAR(200);
EXEC dbo.sp_RecoverStaff @StaffID = @RecStaffID, @AsOfDateTime = @GoodStaffTime, @Success = @Success OUTPUT, @Message = @Msg OUTPUT;
SELECT @Success AS Success, @Msg AS Message;
REVERT;
-- Expected: Success = 1

SELECT Salary FROM dbo.Staff WHERE StaffID = @RecStaffID;
-- Expected: 4500.00 -- the mistaken 999999.00 is gone

-- ---------- sp_RecoverStaff: Scenario B (restore a deleted row) ----------
DELETE FROM dbo.Staff WHERE StaffID = @RecStaffID;

SELECT COUNT(*) AS ShouldBeZero FROM dbo.Staff WHERE StaffID = @RecStaffID;

EXECUTE AS USER = 'test_dba_user';
DECLARE @Success2 BIT, @Msg2 NVARCHAR(200);
EXEC dbo.sp_RecoverStaff @StaffID = @RecStaffID, @AsOfDateTime = @GoodStaffTime, @Success = @Success2 OUTPUT, @Message = @Msg2 OUTPUT;
SELECT @Success2 AS Success, @Msg2 AS Message;
REVERT;
-- Expected: Success = 1, 'Staff record restored (it had been deleted).'

SELECT StaffID, StaffName, Salary FROM dbo.Staff WHERE StaffID = @RecStaffID;
-- Expected: one row, SAME StaffID as before, Salary = 4500.00

-- Final cleanup
DELETE FROM dbo.Staff WHERE StaffID = @RecStaffID;


-- ---------- sp_RecoverCustomer: both scenarios ----------
INSERT INTO dbo.Customer (CustomerName, ICNumber, ICNumberHash, Phone, Address, IsActive)
VALUES ('Recovery Test Customer', ENCRYPTBYPASSPHRASE('TEMP_PLACEHOLDER_KEY', '990101109999'),
        HASHBYTES('SHA2_256', '990101109999'), '0170000001', 'Test Address', 1);
DECLARE @RecCustID INT = SCOPE_IDENTITY();

WAITFOR DELAY '00:00:01';
DECLARE @GoodCustTime DATETIME2 = SYSDATETIME();
WAITFOR DELAY '00:00:01';

UPDATE dbo.Customer SET Address = 'WRONG ADDRESS BY MISTAKE' WHERE CustomerID = @RecCustID;

EXECUTE AS USER = 'test_dba_user';
DECLARE @Success3 BIT, @Msg3 NVARCHAR(200);
EXEC dbo.sp_RecoverCustomer @CustomerID = @RecCustID, @AsOfDateTime = @GoodCustTime, @Success = @Success3 OUTPUT, @Message = @Msg3 OUTPUT;
SELECT @Success3 AS Success, @Msg3 AS Message;
REVERT;

SELECT Address FROM dbo.Customer WHERE CustomerID = @RecCustID;
-- Expected: 'Test Address' -- the mistaken address is gone

DELETE FROM dbo.Customer WHERE CustomerID = @RecCustID;

EXECUTE AS USER = 'test_dba_user';
DECLARE @Success4 BIT, @Msg4 NVARCHAR(200);
EXEC dbo.sp_RecoverCustomer @CustomerID = @RecCustID, @AsOfDateTime = @GoodCustTime, @Success = @Success4 OUTPUT, @Message = @Msg4 OUTPUT;
SELECT @Success4 AS Success, @Msg4 AS Message;
REVERT;
-- Expected: Success = 1, restored with the SAME CustomerID

SELECT CustomerID, CustomerName, Address FROM dbo.Customer WHERE CustomerID = @RecCustID;

DELETE FROM dbo.Customer WHERE CustomerID = @RecCustID;


-- ---------- sp_RecoverAccount: both scenarios ----------
-- Uses CustomerID 2 (Aiman, already active) as the owning customer
INSERT INTO dbo.Account (CustomerID, AccountType, Balance, IsActive)
VALUES (2, 'Savings', 1000.00, 1);
DECLARE @RecAccID INT = SCOPE_IDENTITY();

WAITFOR DELAY '00:00:01';
DECLARE @GoodAccTime DATETIME2 = SYSDATETIME();
WAITFOR DELAY '00:00:01';

UPDATE dbo.Account SET Balance = 0.00 WHERE AccountID = @RecAccID;  -- the "mistake"

EXECUTE AS USER = 'test_dba_user';
DECLARE @Success5 BIT, @Msg5 NVARCHAR(200);
EXEC dbo.sp_RecoverAccount @AccountID = @RecAccID, @AsOfDateTime = @GoodAccTime, @Success = @Success5 OUTPUT, @Message = @Msg5 OUTPUT;
SELECT @Success5 AS Success, @Msg5 AS Message;
REVERT;

SELECT Balance FROM dbo.Account WHERE AccountID = @RecAccID;
-- Expected: 1000.00

DELETE FROM dbo.Account WHERE AccountID = @RecAccID;

EXECUTE AS USER = 'test_dba_user';
DECLARE @Success6 BIT, @Msg6 NVARCHAR(200);
EXEC dbo.sp_RecoverAccount @AccountID = @RecAccID, @AsOfDateTime = @GoodAccTime, @Success = @Success6 OUTPUT, @Message = @Msg6 OUTPUT;
SELECT @Success6 AS Success, @Msg6 AS Message;
REVERT;
-- Expected: Success = 1, restored with the SAME AccountID and Balance = 1000.00

SELECT AccountID, Balance FROM dbo.Account WHERE AccountID = @RecAccID;

DELETE FROM dbo.Account WHERE AccountID = @RecAccID;


-- ---------- sp_RecoverTransactionRecord: both scenarios ----------
-- Uses AccountID 2 (Aiman's Savings) -- a genuine leaf row, nothing
-- references TransactionRecord via FK, so deletion is always clean
INSERT INTO dbo.TransactionRecord (AccountID, Amount, TransactionType, ToAccountID)
VALUES (2, 250.00, 'Deposit', NULL);
DECLARE @RecTransID INT = SCOPE_IDENTITY();

WAITFOR DELAY '00:00:01';
DECLARE @GoodTransTime DATETIME2 = SYSDATETIME();
WAITFOR DELAY '00:00:01';

UPDATE dbo.TransactionRecord SET Amount = 99999.00 WHERE TransID = @RecTransID;  -- the "mistake"

EXECUTE AS USER = 'test_dba_user';
DECLARE @Success7 BIT, @Msg7 NVARCHAR(200);
EXEC dbo.sp_RecoverTransactionRecord @TransID = @RecTransID, @AsOfDateTime = @GoodTransTime, @Success = @Success7 OUTPUT, @Message = @Msg7 OUTPUT;
SELECT @Success7 AS Success, @Msg7 AS Message;
REVERT;

SELECT Amount FROM dbo.TransactionRecord WHERE TransID = @RecTransID;
-- Expected: 250.00

DELETE FROM dbo.TransactionRecord WHERE TransID = @RecTransID;

EXECUTE AS USER = 'test_dba_user';
DECLARE @Success8 BIT, @Msg8 NVARCHAR(200);
EXEC dbo.sp_RecoverTransactionRecord @TransID = @RecTransID, @AsOfDateTime = @GoodTransTime, @Success = @Success8 OUTPUT, @Message = @Msg8 OUTPUT;
SELECT @Success8 AS Success, @Msg8 AS Message;
REVERT;
-- Expected: Success = 1, restored with the SAME TransID and Amount = 250.00

SELECT TransID, Amount FROM dbo.TransactionRecord WHERE TransID = @RecTransID;

DELETE FROM dbo.TransactionRecord WHERE TransID = @RecTransID;

-- ---------- Negative test: non-DBA blocked at Layer 1 ----------
EXECUTE AS USER = 'test_manager_user';
DECLARE @Success9 BIT, @Msg9 NVARCHAR(200);
EXEC dbo.sp_RecoverStaff @StaffID = 7, @AsOfDateTime = SYSDATETIME(), @Success = @Success9 OUTPUT, @Message = @Msg9 OUTPUT;
REVERT;
-- Expected: "EXECUTE permission was denied" error

PRINT 'Part 9 (Recovery Procedures) test suite complete.';
GO


-- ################################################################
-- TASK #10 TEST CASES -- Backup Automation
-- Scheduled jobs can't be demonstrated by waiting hours/minutes
-- live, so verification splits into two parts: confirming the
-- jobs/schedules are correctly registered, and confirming the
-- underlying backup procedures actually work when called directly
-- (which is exactly what the scheduler will do on its own later).
-- ================================================================

-- TEST 1: all 3 jobs exist and are enabled
SELECT name, enabled FROM msdb.dbo.sysjobs WHERE name LIKE N'SmartBankDB%';
-- Expected: 3 rows, enabled = 1 for all

-- TEST 2: each job has its schedule correctly attached
SELECT j.name AS JobName, s.name AS ScheduleName, s.freq_subday_type, s.freq_subday_interval
FROM msdb.dbo.sysjobs j
JOIN msdb.dbo.sysjobschedules js ON j.job_id = js.job_id
JOIN msdb.dbo.sysschedules s ON js.schedule_id = s.schedule_id
WHERE j.name LIKE N'SmartBankDB%';
-- Expected: 3 rows -- Full/freq_subday_interval=6 (hours),
-- Differential/freq_subday_interval=1 (hours), Log/freq_subday_interval=5 (minutes)

-- TEST 3: each job is registered to actually run on this server
-- (a job with no jobserver assigned never fires, even if enabled)
SELECT j.name FROM msdb.dbo.sysjobs j
JOIN msdb.dbo.sysjobservers js ON j.job_id = js.job_id
WHERE j.name LIKE N'SmartBankDB%';
-- Expected: 3 rows

-- TEST 4: the underlying backup procedures actually work when
