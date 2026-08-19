-- SALSABILA (TP078641) CONFIDENTIALITY // ANONYMISATION
/* ================================================================
   Task C5: Anonymisation — Account and TransactionRecord data extracted for
   analytical reporting, with all customer identity stripped and
   replaced by a randomly generated surrogate key.

   Report reference : Section 3.3 (Anonymisation), 4.8 (part 2)
   Weakness addressed: Weakness 10 (no anonymisation for
   non-production/analytical use)

   ================================================================ */

-- IMPLEMENTATION >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>.
USE SmartBankDB;
GO

/* ================================================================
   [C5.1] ANALYTICS DATABASE + TABLES
   Separate from SmartBankDB_Dev (C4) — a distinct destination for
   a distinct purpose (identity-free aggregate reporting, not
   realistic-looking test records).
   ================================================================ */
IF DB_ID('SmartBankDB_Analytics') IS NULL
BEGIN
    CREATE DATABASE SmartBankDB_Analytics;
END
GO

USE SmartBankDB_Analytics;
GO

IF OBJECT_ID('dbo.Account_Anonymized', 'U') IS NOT NULL DROP TABLE dbo.Account_Anonymized;
CREATE TABLE dbo.Account_Anonymized (
    AccountID INT PRIMARY KEY,             -- kept: Internal/Low risk on its own (Table 1)
    SurrogateCustomerID UNIQUEIDENTIFIER,  -- replaces real CustomerID entirely
    AccountType NVARCHAR(20),
    Balance DECIMAL(15,2),
    IsActive BIT
);
GO

IF OBJECT_ID('dbo.TransactionRecord_Anonymized', 'U') IS NOT NULL DROP TABLE dbo.TransactionRecord_Anonymized;
CREATE TABLE dbo.TransactionRecord_Anonymized (
    TransID INT PRIMARY KEY,
    AccountID INT,               -- kept: no direct customer-identifying data in this table
    TransDate DATETIME2,
    Amount DECIMAL(15,2),
    TransactionType NVARCHAR(20),
    ToAccountID INT NULL
);
GO

USE SmartBankDB;
GO

/* ================================================================
   [C5.2] REFRESH PROCEDURE
   Generates one random surrogate ID per DISTINCT real customer
   (never per source row), then populates both anonymized tables.
   No WITH EXECUTE AS OWNER — runs under caller's context, matching
   the working design from C4 after the cross-database lesson.
   ================================================================ */
CREATE OR ALTER PROCEDURE dbo.sp_RefreshAnalyticsData
AS
BEGIN
    SET NOCOUNT ON;

    -- Temporary surrogate mapping: exactly ONE random surrogate per
    -- DISTINCT real CustomerID. The inner subquery deduplicates
    -- CustomerID FIRST, so NEWID() below runs once per distinct
    -- customer, not once per Account row — this is what guarantees
    -- a customer with multiple accounts gets the SAME surrogate
    -- consistently across all their rows in this extraction.
    IF OBJECT_ID('tempdb..#SurrogateMap') IS NOT NULL DROP TABLE #SurrogateMap;

    SELECT
        CustomerID AS RealCustomerID,
        NEWID() AS SurrogateCustomerID
    INTO #SurrogateMap
    FROM (SELECT DISTINCT CustomerID FROM SmartBankDB.dbo.Account) AS DistinctCustomers;

    -- Populate Account_Anonymized: real CustomerID replaced by
    -- surrogate; CustomerName/ICNumber/Phone/Address never touched
    -- or copied at all — not even read from the source table.
    TRUNCATE TABLE SmartBankDB_Analytics.dbo.Account_Anonymized;

    INSERT INTO SmartBankDB_Analytics.dbo.Account_Anonymized
        (AccountID, SurrogateCustomerID, AccountType, Balance, IsActive)
    SELECT
        a.AccountID,
        m.SurrogateCustomerID,
        a.AccountType,
        a.Balance,
        a.IsActive
    FROM SmartBankDB.dbo.Account a
    JOIN #SurrogateMap m ON a.CustomerID = m.RealCustomerID;

    -- Populate TransactionRecord_Anonymized: straightforward copy.
    -- No customer-identifying columns exist in this table at all.
    TRUNCATE TABLE SmartBankDB_Analytics.dbo.TransactionRecord_Anonymized;

    INSERT INTO SmartBankDB_Analytics.dbo.TransactionRecord_Anonymized
        (TransID, AccountID, TransDate, Amount, TransactionType, ToAccountID)
    SELECT
        TransID, AccountID, TransDate, Amount, TransactionType, ToAccountID
    FROM SmartBankDB.dbo.TransactionRecord;

    DROP TABLE #SurrogateMap;
END;
GO

/* ================================================================
   [C5.3] ACCESS RESTRICTION
   Only the DBA role may trigger an analytics extraction — same
   infrastructure-management reasoning as C4.
   ================================================================ */
GRANT EXECUTE ON dbo.sp_RefreshAnalyticsData TO DBA;
GO
GRANT SELECT ON dbo.Account TO DBA;
GO
GRANT SELECT ON dbo.TransactionRecord TO DBA;
GO


/* ================================================================
   [C5.4] INITIAL POPULATION
   ================================================================ */
EXEC dbo.sp_RefreshAnalyticsData;
GO


/* ================================================================
   [C5.5] DOCUMENTATION — FRESH SURROGATES PER RUN
   No code required. Every execution of sp_RefreshAnalyticsData
   generates a BRAND NEW random surrogate mapping (the #SurrogateMap
   temp table is rebuilt from scratch each time). This means the
   surrogate assigned to a given real customer will differ between
   one extraction run and the next — a deliberate design choice
   preventing an analyst from correlating a person's activity
   pattern ACROSS separate reporting periods just by recognizing a
   repeated surrogate ID. This is a stronger anonymisation guarantee
   than a stable, persistent mapping would provide.
   ================================================================ */

PRINT 'C5 — Anonymisation for analytical reporting complete.';


-- TEST CASE >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
/* ================================================================
   PERSON C — TASK C5 TEST CASES
   Run this AFTER C5_Anonymisation.sql has executed successfully.
   ================================================================ */

USE SmartBankDB;
GO


/* ================================================================
   ONE-TIME SETUP — confirm/create test users (reused pattern)
   ================================================================ */
USE master;
GO
IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name = 'test_officer_login')
    CREATE LOGIN test_officer_login WITH PASSWORD = 'Str0ngTestPass!123';
GO

USE SmartBankDB;
GO
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = 'test_officer_user')
    CREATE USER test_officer_user FOR LOGIN test_officer_login;
GO
IF NOT EXISTS (SELECT 1 FROM sys.database_role_members drm
                JOIN sys.database_principals r ON drm.role_principal_id = r.principal_id
                JOIN sys.database_principals m ON drm.member_principal_id = m.principal_id
                WHERE r.name = 'Bank_Officer' AND m.name = 'test_officer_user')
    ALTER ROLE Bank_Officer ADD MEMBER test_officer_user;
GO


/* ================================================================
   T-C5.1 — POSITIVE: analytics tables exist with matching row counts
   ================================================================ */
PRINT '--- T-C5.1: checking row counts match source data ---';

SELECT
    (SELECT COUNT(*) FROM SmartBankDB.dbo.Account) AS ProdAccountCount,
    (SELECT COUNT(*) FROM SmartBankDB_Analytics.dbo.Account_Anonymized) AS AnonAccountCount,
    (SELECT COUNT(*) FROM SmartBankDB.dbo.TransactionRecord) AS ProdTransCount,
    (SELECT COUNT(*) FROM SmartBankDB_Analytics.dbo.TransactionRecord_Anonymized) AS AnonTransCount;
-- Expected: counts match exactly on both pairs
GO


/* ================================================================
   T-C5.2 — POSITIVE: procedure runs successfully
   ================================================================ */
PRINT '--- T-C5.2: re-running the refresh ---';

EXEC dbo.sp_RefreshAnalyticsData;
PRINT 'Refresh completed with no errors.';
GO


/* ================================================================
   T-C5.3 — POSITIVE: no real CustomerID values appear anywhere in
   the anonymized Account table
   ================================================================ */
PRINT '--- T-C5.3: confirming no real CustomerID leaked into Account_Anonymized ---';

SELECT COUNT(*) AS ColumnsNamedCustomerID
FROM SmartBankDB_Analytics.INFORMATION_SCHEMA.COLUMNS
WHERE TABLE_NAME = 'Account_Anonymized' AND COLUMN_NAME = 'CustomerID';
-- Expected: 0 — the column doesn't exist AT ALL, not just hidden
GO


/* ================================================================
   T-C5.4 — POSITIVE: a customer with multiple accounts gets the
   SAME surrogate ID consistently across all their accounts
   ================================================================ */
PRINT '--- T-C5.4: checking surrogate consistency for multi-account customers ---';

SELECT
    p.CustomerID AS RealCustomerID,
    COUNT(DISTINCT a.SurrogateCustomerID) AS DistinctSurrogatesUsed
FROM SmartBankDB.dbo.Account p
JOIN SmartBankDB_Analytics.dbo.Account_Anonymized a ON p.AccountID = a.AccountID
GROUP BY p.CustomerID
HAVING COUNT(*) > 1;
-- Expected: for every real customer with multiple accounts,
-- DistinctSurrogatesUsed = 1 (same surrogate every time, this run)
GO


/* ================================================================
   T-C5.5 — POSITIVE: no identity columns exist AT ALL in the
   anonymized schema (structural check, not just empty values)
   ================================================================ */
PRINT '--- T-C5.5: confirming CustomerName/ICNumber/Phone/Address columns do not exist ---';

SELECT COLUMN_NAME
FROM SmartBankDB_Analytics.INFORMATION_SCHEMA.COLUMNS
WHERE TABLE_NAME IN ('Account_Anonymized', 'TransactionRecord_Anonymized')
  AND COLUMN_NAME IN ('CustomerName', 'ICNumber', 'ICNumberHash', 'Phone', 'Address');
-- Expected: 0 rows returned — none of these columns exist anywhere
-- in the analytics schema
GO


/* ================================================================
   T-C5.6 — POSITIVE: relational integrity preserved — every
   transaction's AccountID correctly links to an anonymized account
   ================================================================ */
PRINT '--- T-C5.6: checking TransactionRecord_Anonymized links correctly ---';

SELECT COUNT(*) AS OrphanedTransactions
FROM SmartBankDB_Analytics.dbo.TransactionRecord_Anonymized t
LEFT JOIN SmartBankDB_Analytics.dbo.Account_Anonymized a ON t.AccountID = a.AccountID
WHERE a.AccountID IS NULL;
-- Expected: 0 — every transaction correctly links to an existing
-- anonymized account, so aggregate analysis (e.g. "total
-- transactions per anonymous customer") remains possible
GO


/* ================================================================
   T-C5.7 — POSITIVE: fresh surrogate mapping differs between runs
   ================================================================ */
PRINT '--- T-C5.7: comparing surrogate IDs across two separate runs ---';

SELECT AccountID, SurrogateCustomerID AS SurrogateID_Run1
INTO #Run1Snapshot
FROM SmartBankDB_Analytics.dbo.Account_Anonymized;

EXEC dbo.sp_RefreshAnalyticsData;   -- second run

SELECT
    r1.AccountID,
    r1.SurrogateID_Run1,
    a2.SurrogateCustomerID AS SurrogateID_Run2
FROM #Run1Snapshot r1
JOIN SmartBankDB_Analytics.dbo.Account_Anonymized a2 ON r1.AccountID = a2.AccountID;
-- Expected: SurrogateID_Run1 and SurrogateID_Run2 are DIFFERENT
-- for every row — confirms a fresh random mapping each run,
-- preventing cross-run correlation

DROP TABLE #Run1Snapshot;
GO


/* ================================================================
   T-C5.8 — NEGATIVE: non-DBA role blocked from running the refresh
   ================================================================ */
PRINT '--- T-C5.8: Bank_Officer attempting to run sp_RefreshAnalyticsData ---';

EXECUTE AS USER = 'test_officer_user';
EXEC dbo.sp_RefreshAnalyticsData;
-- Expected: Msg 229 EXECUTE permission denied
REVERT;
GO


/* ================================================================
   CLEANUP
   ================================================================ */
PRINT '--- Cleaning up test user ---';

IF EXISTS (SELECT 1 FROM sys.database_principals WHERE name = 'test_officer_user')
    DROP USER test_officer_user;
GO

PRINT 'C5 test suite complete.';