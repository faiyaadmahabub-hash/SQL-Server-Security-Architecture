USE SmartBankDB;
GO

-- ================================================================
-- TASK #3: SET UP THE 4 ROLES
-- ================================================================

-- ================================================================
-- Component: Create 4 database roles
-- (Fixes Weakness 2 -- previously all users shared one connection
-- with no roles at all. These 4 roles match the 4 user types
-- defined in the assignment brief and Section 3.1 of our report.)
-- ================================================================
CREATE ROLE DBA;
GO
CREATE ROLE Bank_Manager;
GO
CREATE ROLE Bank_Officer;
GO
CREATE ROLE Customer;
GO


-- ================================================================
-- Component: Deny direct base-table access by default
-- (Enforces the report's core rule: "No role has direct SELECT,
-- INSERT, UPDATE, or DELETE permissions on any base table."
-- SQL Server already blocks access by default unless granted, but
-- we DENY explicitly here so it's provable and demonstrable --
-- DENY always overrides any GRANT, so this acts as a safety net
-- even if someone accidentally grants table access later.)
-- ================================================================
DENY SELECT, INSERT, UPDATE, DELETE ON dbo.Staff             TO DBA, Bank_Manager, Bank_Officer, Customer;
DENY SELECT, INSERT, UPDATE, DELETE ON dbo.Customer          TO DBA, Bank_Manager, Bank_Officer, Customer;
DENY SELECT, INSERT, UPDATE, DELETE ON dbo.Account           TO DBA, Bank_Manager, Bank_Officer, Customer;
DENY SELECT, INSERT, UPDATE, DELETE ON dbo.TransactionRecord TO DBA, Bank_Manager, Bank_Officer, Customer;
DENY SELECT, INSERT, UPDATE, DELETE ON dbo.PendingApproval   TO DBA, Bank_Manager, Bank_Officer, Customer;
GO


-- ================================================================
-- Component: DBA schema/DDL rights
-- (Fixes Weakness 19 -- resolves the brief's Integrity requirement
-- "Only DBAs may create and manage tables (not data)." Uses
-- built-in db_ddladmin membership, which grants CREATE/ALTER/DROP
-- on tables and other schema objects, but NOT data access.)
-- ================================================================
ALTER ROLE db_ddladmin ADD MEMBER DBA;
GO


-- ================================================================
-- Component: DBA explicitly denied data access
-- (This looks redundant with the DENY block above, but it's kept
-- as a separate, clearly-commented statement so the report and
-- demo can point directly at "here is where we guarantee schema
-- rights never imply data rights" -- makes the separation obvious
-- rather than implicit.)
-- ================================================================
-- Already covered by the DENY block above -- DBA remains denied
-- on Staff/Customer/Account/TransactionRecord/PendingApproval even
-- after being added to db_ddladmin, since DENY always wins over
-- any GRANT or role membership.


-- ================================================================
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