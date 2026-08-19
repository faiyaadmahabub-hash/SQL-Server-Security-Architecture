-- SALSABILA (TP078641) CONFIDENTIALITY TC1 // DYNAMIC DATA MASKING
/* ================================================================
   Task C1 : Dynamic Data Masking (DDM) on Account.Balance — Bank Officers
   see only a partial value, Bank Managers and Customers see the
   true balance.

   Report reference : Section 3.3 (Dynamic Data Masking), 4.5
   Weakness addressed: Weakness 7 (Bank Officer over-exposure to
   full account balances)
   ================================================================ */


-- IMPLEMENTATION OF DYNAMIC DATA MASKING >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

USE SmartBankDB;
GO

/* ================================================================
   [C1.1] APPLY DYNAMIC DATA MASKING TO Account.Balance
   partial(prefix, padding, suffix): shows 0 characters at the
   start, replaces the middle with the padding string, then shows
   the last 2 characters of the value as stored/displayed.
   ================================================================ */

-- This fully masks Balance to 0.00 for anyone without UNMASK, rather than showing a partial last-2-digits value.
ALTER TABLE dbo.Account
ALTER COLUMN Balance ADD MASKED WITH (FUNCTION = 'default()');
GO

-- Confirm the mask was applied
SELECT
    t.name AS TableName,
    c.name AS ColumnName,
    c.is_masked,
    c.masking_function
FROM sys.masked_columns c
JOIN sys.tables t ON c.object_id = t.object_id
WHERE t.name = 'Account';
GO

/* ================================================================
   [C1.2] GRANT UNMASK TO Bank_Manager
   Database-wide UNMASK — currently Balance is the only masked
   column in the whole database, so this is equivalent in scope to
   a column-level grant for now. If more masked columns are added
   later by any teammate, revisit this to confirm Bank_Manager
   should see those too, or migrate to column-scoped UNMASK if the
   SQL Server version supports it (2022+).
   ================================================================ */
GRANT UNMASK TO Bank_Manager;
GO

/* ================================================================
   [C1.3] GRANT UNMASK TO Customer
   Customers must see their true balance on their own accounts
   (via Person B's vw_AccountOwn, which reads from this column).
   ================================================================ */
GRANT UNMASK TO Customer;
GO

/* ================================================================
   [C1.4] NO GRANT TO Bank_Officer — INTENTIONAL, NO CODE HERE
   SQL Server denies UNMASK by default. Since Bank_Officer is never
   granted it, any query an Officer runs against Balance — whether
   directly on the table or through a view — automatically returns
   the masked value. No DENY statement needed or wanted (same
   default-deny principle applied consistently since C6).
   ================================================================ */
PRINT 'Reminder: Bank_Officer intentionally has no UNMASK grant — will always see masked Balance values.';
GO

/* ================================================================
   [C1.5] DOCUMENTATION — MASKING IS DISPLAY-ONLY
   No code required. Masking never changes the value actually
   stored on disk, and never affects server-side computation:
   WHERE clauses, JOINs, SUM()/aggregate functions, and stored
   procedure arithmetic (e.g. Person D's sp_PerformTransaction
   adjusting a real balance) all continue to operate on the TRUE
   value internally, regardless of who is running the query or
   whether they hold UNMASK. Masking only changes what a SELECT
   query displays back as its final result set.
   ================================================================ */

PRINT 'C1 — Dynamic Data Masking on Account.Balance complete.';

-- TEST CASE >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
/* ================================================================
   PERSON C — TASK C1 TEST CASES
   Run this AFTER C1_Dynamic_Data_Masking.sql has executed
   successfully.

   Since Person B's views (vw_AccountAll, vw_AccountOwn) may not
   exist yet, this test suite grants TEMPORARY direct SELECT on
   dbo.Account to the test users, purely to test masking behavior
   in isolation. Production access will go through B's views per
   Table 5 — flagged clearly below, and revoked in cleanup.

   Reuses test_manager_user, test_officer_user, test_customer_user
   from earlier test suites (C2/C3) — recreated here defensively
   with IF NOT EXISTS in case this is a fresh session.
   ================================================================ */

USE SmartBankDB;
GO


/* ================================================================
   ONE-TIME SETUP — confirm/create test users, then grant TEMPORARY
   direct SELECT on Account for isolated masking tests only.
   ================================================================ */
USE master;
GO
IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name = 'test_manager_login')
    CREATE LOGIN test_manager_login WITH PASSWORD = 'Str0ngTestPass!123';
IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name = 'test_officer_login')
    CREATE LOGIN test_officer_login WITH PASSWORD = 'Str0ngTestPass!123';
IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name = 'test_customer_login')
    CREATE LOGIN test_customer_login WITH PASSWORD = 'Str0ngTestPass!123';
GO

USE SmartBankDB;
GO
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = 'test_manager_user')
    CREATE USER test_manager_user FOR LOGIN test_manager_login;
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = 'test_officer_user')
    CREATE USER test_officer_user FOR LOGIN test_officer_login;
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = 'test_customer_user')
    CREATE USER test_customer_user FOR LOGIN test_customer_login;
GO

IF NOT EXISTS (SELECT 1 FROM sys.database_role_members drm
                JOIN sys.database_principals r ON drm.role_principal_id = r.principal_id
                JOIN sys.database_principals m ON drm.member_principal_id = m.principal_id
                WHERE r.name = 'Bank_Manager' AND m.name = 'test_manager_user')
    ALTER ROLE Bank_Manager ADD MEMBER test_manager_user;
IF NOT EXISTS (SELECT 1 FROM sys.database_role_members drm
                JOIN sys.database_principals r ON drm.role_principal_id = r.principal_id
                JOIN sys.database_principals m ON drm.member_principal_id = m.principal_id
                WHERE r.name = 'Bank_Officer' AND m.name = 'test_officer_user')
    ALTER ROLE Bank_Officer ADD MEMBER test_officer_user;
IF NOT EXISTS (SELECT 1 FROM sys.database_role_members drm
                JOIN sys.database_principals r ON drm.role_principal_id = r.principal_id
                JOIN sys.database_principals m ON drm.member_principal_id = m.principal_id
                WHERE r.name = 'Customer' AND m.name = 'test_customer_user')
    ALTER ROLE Customer ADD MEMBER test_customer_user;
GO

-- TEMPORARY, testing-only direct table access (see header note)
GRANT SELECT ON dbo.Account TO Bank_Manager;
GRANT SELECT ON dbo.Account TO Bank_Officer;
GRANT SELECT ON dbo.Account TO Customer;
GO


/* ================================================================
   T-C1.1 — POSITIVE: Bank_Manager sees the TRUE balance
   ================================================================ */
PRINT '--- T-C1.1: Bank_Manager viewing Balance ---';

EXECUTE AS USER = 'test_manager_user';
SELECT TOP 5 AccountID, CustomerID, AccountType, Balance
FROM dbo.Account;
-- Expected: real, precise Balance values (e.g. 3200.00)
REVERT;
GO


/* ================================================================
   T-C1.2 — POSITIVE: Customer sees the TRUE balance
   ================================================================ */
PRINT '--- T-C1.2: Customer viewing Balance ---';

EXECUTE AS USER = 'test_customer_user';
SELECT TOP 5 AccountID, CustomerID, AccountType, Balance
FROM dbo.Account;
-- Expected: real, precise Balance values
REVERT;
GO


/* ================================================================
   T-C1.3 — NEGATIVE: Bank_Officer sees the MASKED balance
   ================================================================ */
PRINT '--- T-C1.3: Bank_Officer viewing Balance (should be masked) ---';

EXECUTE AS USER = 'test_officer_user';
SELECT TOP 5 AccountID, CustomerID, AccountType, Balance
FROM dbo.Account;
-- Expected: Balance shows a masked pattern (bcs of sql limitation, masked = equate to 0.00), NOT
-- the true precise value
REVERT;
GO


/* ================================================================
   T-C1.4 — NEGATIVE: Bank_Officer cannot bypass masking via
   arithmetic tricks (e.g. adding zero, casting)
   ================================================================ */
PRINT '--- T-C1.4: Bank_Officer attempting to bypass masking ---';

EXECUTE AS USER = 'test_officer_user';
SELECT TOP 5 AccountID, Balance, Balance + 0 AS BalancePlusZero, CONVERT(VARCHAR(20), Balance) AS BalanceAsString
FROM dbo.Account;
-- Expected: ALL THREE columns show masked values — masking
-- applies at the storage-access layer, not just raw display
REVERT;
GO


/* ================================================================
   T-C1.5 — POSITIVE: masking does not corrupt server-side
   computation — SUM() on the real underlying data still works
   correctly regardless of who is querying
   ================================================================ */
PRINT '--- T-C1.5: confirming SUM(Balance) is unaffected by masking ---';

DECLARE @SumAsManager DECIMAL(15,2);
DECLARE @SumAsOfficer DECIMAL(15,2);

EXECUTE AS USER = 'test_manager_user';
SELECT @SumAsManager = SUM(Balance) FROM dbo.Account;
REVERT;

EXECUTE AS USER = 'test_officer_user';
SELECT @SumAsOfficer = SUM(Balance) FROM dbo.Account;
REVERT;

SELECT @SumAsManager AS SumAsManager, @SumAsOfficer AS SumAsOfficer;
-- Expected: BOTH values are IDENTICAL — proves masking only
-- affects final display of individual row values, not aggregate
-- computation over the true underlying data
GO


/* ================================================================
   T-C1.6 — POSITIVE: masked column format matches expectation
   ================================================================ */
PRINT '--- T-C1.6: checking exact masked output format ---';

EXECUTE AS USER = 'test_officer_user';
SELECT TOP 3 AccountID, Balance
FROM dbo.Account;
-- Expected: consistent partial-mask pattern across all rows
-- (or 0.00 for every row, if the [C1.1] fallback was used instead)
REVERT;
GO

/* ================================================================
   CLEANUP — remove the TEMPORARY direct table grants used for
   isolated testing (production access will go through Person B's
   views instead, per Table 5's design)
   ================================================================ */
PRINT '--- Cleaning up temporary test grants ---';

REVOKE SELECT ON dbo.Account FROM Bank_Manager;
REVOKE SELECT ON dbo.Account FROM Bank_Officer;
REVOKE SELECT ON dbo.Account FROM Customer;
GO

PRINT 'C1 test suite complete.';