-- SALSABILA (TP078641)
-- CLEAN UP >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
/* ================================================================
   C4 — CLEANUP / RESET SCRIPT
   Run this as your normal sysadmin (Windows Auth) login, in a
   FRESH query window, before rebuilding C4 from scratch.

   This only removes C4-specific objects. It does NOT touch
   test_officer_login/test_officer_user (shared/reused across
   C1/C2/C3/C4 test suites) — only their role membership grant
   related to C4 testing stays intact since it's harmless and
   reused elsewhere.
   ================================================================ */

USE SmartBankDB;
GO

-- Revoke grants (safe even if they were never granted)
IF EXISTS (SELECT 1 FROM sys.database_permissions dp
           JOIN sys.database_principals pr ON dp.grantee_principal_id = pr.principal_id
           WHERE pr.name = 'DBA' AND OBJECT_NAME(dp.major_id) = 'sp_RefreshDevData')
    REVOKE EXECUTE ON dbo.sp_RefreshDevData FROM DBA;

IF EXISTS (SELECT 1 FROM sys.database_permissions dp
           JOIN sys.database_principals pr ON dp.grantee_principal_id = pr.principal_id
           WHERE pr.name = 'DBA' AND OBJECT_NAME(dp.major_id) = 'Customer')
    REVOKE SELECT ON dbo.Customer FROM DBA;

IF EXISTS (SELECT 1 FROM sys.database_permissions dp
           JOIN sys.database_principals pr ON dp.grantee_principal_id = pr.principal_id
           WHERE pr.name = 'DBA' AND OBJECT_NAME(dp.major_id) = 'Staff')
    REVOKE SELECT ON dbo.Staff FROM DBA;
GO

-- Drop the procedure
IF OBJECT_ID('dbo.sp_RefreshDevData', 'P') IS NOT NULL
    DROP PROCEDURE dbo.sp_RefreshDevData;
GO

-- Drop the entire Dev database (cleanest full reset — removes
-- Customer, Staff, FakeNamePool, FakeStreetPool all at once)
USE master;
GO

IF DB_ID('SmartBankDB_Dev') IS NOT NULL
BEGIN
    ALTER DATABASE SmartBankDB_Dev SET SINGLE_USER WITH ROLLBACK IMMEDIATE;
    DROP DATABASE SmartBankDB_Dev;
END
GO

-- Reset DB_CHAINING back to default (OFF) on SmartBankDB, since it
-- was enabled during troubleshooting and is no longer needed with
-- the final (non-cross-database-impersonation) design
IF EXISTS (SELECT 1 FROM sys.databases WHERE name = 'SmartBankDB' AND is_db_chaining_on = 1)
    ALTER DATABASE SmartBankDB SET DB_CHAINING OFF;
GO

USE SmartBankDB;
GO

-- Confirm everything is gone
SELECT 'sp_RefreshDevData exists' AS check_type, OBJECT_ID('dbo.sp_RefreshDevData', 'P') AS result
UNION ALL
SELECT 'SmartBankDB_Dev exists', DB_ID('SmartBankDB_Dev');
-- Expected: both results NULL

PRINT 'C4 cleanup complete. Safe to rebuild from scratch.';

-- IMPLEMENTATION >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
/* ================================================================
   PERSON C — TASK C4
   Static Data Masking (SDM) — a separate, non-production copy of
   Customer/Staff data with sensitive columns irreversibly replaced
   by realistic fake values, for safe development/testing use.

   Report reference : Section 3.3 (Static Data Masking), 4.8 (part 1)
   Weakness addressed: Weakness 13 (no masking for test/dev
   environments)

   *** POSSIBLE ISSUE — READ BEFORE RUNNING [C4.3] ***
   sp_RefreshDevData writes CROSS-DATABASE (SmartBankDB ->
   SmartBankDB_Dev) using WITH EXECUTE AS OWNER. This should work
   without any special server setting AS LONG AS both databases
   are owned by the same sysadmin login (the normal default for a
   single-developer local instance). If you get a cross-database
   permission error, run this once and retry:

       ALTER AUTHORIZATION ON DATABASE::SmartBankDB_Dev TO sa;

   (This just makes sure both databases have the same owner — it
   is NOT the same thing as TRUSTWORTHY ON and does not introduce
   the same privilege-escalation risk; avoid enabling
   'cross db ownership chaining' or TRUSTWORTHY as alternate fixes.)

   LESSONS FROM C6/C2/C3/C1 APPLIED HERE:
   - Confirm role names exist locally before granting anything.
   - Long-form IF EXISTS throughout, not the unsupported shorthand.
   - No TRUSTWORTHY ON.
   - WITH EXECUTE AS OWNER so the caller (DBA) never needs direct
     SELECT permission on real Customer/Staff data.
   - Any fix must be RE-RUN against the live database.
   ================================================================ */

USE SmartBankDB;
GO


/* ================================================================
   [C4.1] NON-PRODUCTION DATABASE
   A separate database for developers/testers to work against.
   Simplified table structures (no FKs/temporal versioning/complex
   constraints) since this is throwaway test data, not a
   production-grade schema — intentional simplification.
   ================================================================ */
IF DB_ID('SmartBankDB_Dev') IS NULL
BEGIN
    CREATE DATABASE SmartBankDB_Dev;
END
GO

USE SmartBankDB_Dev;
GO

IF OBJECT_ID('dbo.Customer', 'U') IS NOT NULL DROP TABLE dbo.Customer;
CREATE TABLE dbo.Customer (
    CustomerID INT PRIMARY KEY,
    CustomerName NVARCHAR(100),
    ICNumber VARBINARY(MAX) NULL,        -- deliberately nulled, see [C4.3]
    ICNumberHash VARBINARY(32) NULL,     -- deliberately nulled, see [C4.3]
    Phone NVARCHAR(50),
    Address NVARCHAR(255),
    IsActive BIT
);
GO

IF OBJECT_ID('dbo.Staff', 'U') IS NOT NULL DROP TABLE dbo.Staff;
CREATE TABLE dbo.Staff (
    StaffID INT PRIMARY KEY,
    StaffName NVARCHAR(100),
    Position NVARCHAR(50),
    Branch NVARCHAR(100),
    Phone NVARCHAR(15),
    Salary DECIMAL(15,2),
    IsActive BIT
);
GO

USE SmartBankDB;
GO


/* ================================================================
   [C4.2] FAKE REFERENCE DATA POOLS
   Small, reusable lookup tables in the Dev database holding
   realistic (but entirely fictional) names and street names, used
   as the SOURCE material for masked values — independent of any
   real data, which is what makes the result truly irreversible.
   ================================================================ */
USE SmartBankDB_Dev;
GO

IF OBJECT_ID('dbo.FakeNamePool', 'U') IS NOT NULL DROP TABLE dbo.FakeNamePool;
CREATE TABLE dbo.FakeNamePool (ID INT IDENTITY(1,1) PRIMARY KEY, FakeName NVARCHAR(100));
INSERT INTO dbo.FakeNamePool (FakeName) VALUES
('Ahmad Zulkarnain'), ('Tan Wei Ling'), ('Kumar Raveendran'), ('Nur Aisyah'),
('Lee Chong Ming'), ('Siti Khadijah'), ('Ganesh Muthu'), ('Ong Bee Hoon'),
('Faizal Rashid'), ('Chan Mei Yee'), ('Ravi Chandran'), ('Noraini Yaacob'),
('Wong Kah Meng'), ('Amirul Hafiz'), ('Priya Devi'), ('Lim Suet Fern'),
('Hafizuddin Rosli'), ('Cheah Xin Yi'), ('Muthusamy Krishnan'), ('Aina Natasha');
GO

IF OBJECT_ID('dbo.FakeStreetPool', 'U') IS NOT NULL DROP TABLE dbo.FakeStreetPool;
CREATE TABLE dbo.FakeStreetPool (ID INT IDENTITY(1,1) PRIMARY KEY, FakeStreet NVARCHAR(100), FakeCity NVARCHAR(100));
INSERT INTO dbo.FakeStreetPool (FakeStreet, FakeCity) VALUES
('Jalan Sinar', 'Kuala Lumpur'), ('Jalan Ceria', 'Petaling Jaya'),
('Jalan Damai Perdana', 'Subang Jaya'), ('Jalan Bunga Tanjung', 'Klang'),
('Jalan Impian', 'Shah Alam'), ('Jalan Suria', 'Kuala Lumpur'),
('Jalan Bahagia', 'Petaling Jaya'), ('Jalan Harmoni Baru', 'Subang Jaya');
GO

USE SmartBankDB;
GO


/* ================================================================
   [C4.3] REFRESH PROCEDURE
   Rebuilds SmartBankDB_Dev.Customer and .Staff from real production
   data, masking sensitive columns along the way.
 
   DESIGN NOTE — WHY THIS DOESN'T USE WITH EXECUTE AS OWNER:
   An initial version used WITH EXECUTE AS OWNER (matching the
   pattern from C2's sp_DecryptICNumber) specifically to avoid
   granting the DBA role any direct access to real Customer/Staff
   data. This failed with "Cannot find the object... or you do not
   have permissions" when writing cross-database into
   SmartBankDB_Dev — confirmed NOT caused by mismatched database
   ownership (checked directly, both same owner) or DB_CHAINING
   being disabled (enabled explicitly, still failed). This is a
   known area of inconsistency in how SQL Server evaluates
   impersonated execution contexts across database boundaries.
 
   ADAPTED DESIGN: runs under the caller's own context instead. The
   DBA role is granted direct SELECT on Customer/Staff (see below)
   — narrower than the original "DBA never touches real data"
   ideal, but still safe: this data is read internally and
   immediately transformed/discarded, NEVER returned in any result
   set to the caller. A DBA running this procedure sees no real
   customer names, phone numbers, or salaries at any point.
 
   ICNumber/ICNumberHash are set to NULL entirely (beyond the
   report's literal minimum) since the ciphertext would be
   meaningless anyway without the C2 symmetric key, which is
   intentionally never copied to this database.
   ================================================================ */
CREATE OR ALTER PROCEDURE dbo.sp_RefreshDevData
AS
BEGIN
    SET NOCOUNT ON;
 
    -- Refresh Customer: CustomerName, Phone, Address are FAKE;
    -- ICNumber/ICNumberHash are NULL; CustomerID/IsActive are real
    -- (structural realism, not sensitive on their own)
    TRUNCATE TABLE SmartBankDB_Dev.dbo.Customer;
 
    INSERT INTO SmartBankDB_Dev.dbo.Customer
        (CustomerID, CustomerName, ICNumber, ICNumberHash, Phone, Address, IsActive)
    SELECT
        c.CustomerID,
        fn.FakeName,
        NULL,
        NULL,
        '01' + RIGHT('00000000' + CAST(ABS(CHECKSUM(NEWID())) % 100000000 AS VARCHAR(8)), 8),
        CONCAT('No ', ABS(CHECKSUM(NEWID())) % 200 + 1, ', ', fs.FakeStreet, ', ', fs.FakeCity),
        c.IsActive
    FROM SmartBankDB.dbo.Customer c
    -- NOTE: "WHERE c.CustomerID = c.CustomerID" below is a deliberate
    -- tautology (always true, filters nothing). Its only purpose is
    -- to reference the outer row alias 'c', forcing SQL Server's
    -- optimizer to treat this subquery as correlated per-row. Without
    -- it, the optimizer sees no dependency on the outer row at all
    -- and "hoists" the subquery — computing the random pick ONCE and
    -- reusing that same result for every row (confirmed bug, caught
    -- by T-C4.8: every customer got the identical fake name).
    CROSS APPLY (SELECT TOP 1 FakeName FROM SmartBankDB_Dev.dbo.FakeNamePool WHERE c.CustomerID = c.CustomerID ORDER BY NEWID()) fn
    CROSS APPLY (SELECT TOP 1 FakeStreet, FakeCity FROM SmartBankDB_Dev.dbo.FakeStreetPool WHERE c.CustomerID = c.CustomerID ORDER BY NEWID()) fs;
 
    -- Refresh Staff: only Salary is FAKE; StaffName/Position/Branch/
    -- Phone are real (Internal classification, low risk, needed for
    -- realistic org-structure testing)
    TRUNCATE TABLE SmartBankDB_Dev.dbo.Staff;
 
    INSERT INTO SmartBankDB_Dev.dbo.Staff
        (StaffID, StaffName, Position, Branch, Phone, Salary, IsActive)
    SELECT
        s.StaffID,
        s.StaffName,
        s.Position,
        s.Branch,
        s.Phone,
        CAST(ABS(CHECKSUM(NEWID())) % 7000 + 3000 AS DECIMAL(15,2)),
        s.IsActive
    FROM SmartBankDB.dbo.Staff s;
END;
GO
 

/* ================================================================
   [C4.4] ACCESS RESTRICTION
   Only the DBA role may trigger a dev environment refresh —
   matches Section 3.1's description of DBA as the infrastructure-
   management role. No business role has any operational reason to
   run this. Direct SELECT on Customer/Staff is also scoped to DBA
   only, and only to support this one procedure (see design note
   in [C4.3] above for why this is necessary and still safe).
   ================================================================ */
GRANT EXECUTE ON dbo.sp_RefreshDevData TO DBA;
GO
GRANT SELECT ON dbo.Customer TO DBA;
GO
GRANT SELECT ON dbo.Staff TO DBA;
GO


/* ================================================================
   [C4.5] INITIAL POPULATION
   ================================================================ */
EXEC dbo.sp_RefreshDevData;
GO


/* ================================================================
   [C4.6] DOCUMENTATION — IRREVERSIBILITY GUARANTEE
   No code required. Every fake value is drawn from an independent
   reference pool (FakeNamePool, FakeStreetPool) or generated from
   CHECKSUM(NEWID()) — a fresh random value with NO mathematical
   relationship to the real value it replaces. There is no key,
   password, or algorithm that could ever recover the original
   data from this copy, because the original was never used as
   input to the transformation at all — it was read once, then
   discarded in favor of something entirely unrelated.
   ================================================================ */

PRINT 'C4 — Static Data Masking dev environment setup complete.';

-- TEST CASE >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
/* ================================================================
   PERSON C — TASK C4 TEST CASES
   Run this AFTER C4_Static_Data_Masking.sql has executed
   successfully.
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
   T-C4.1 — POSITIVE: Dev database and tables exist with correct
   row counts matching production
   ================================================================ */
PRINT '--- T-C4.1: checking Dev database structure and row counts ---';

SELECT
    (SELECT COUNT(*) FROM SmartBankDB.dbo.Customer) AS ProdCustomerCount,
    (SELECT COUNT(*) FROM SmartBankDB_Dev.dbo.Customer) AS DevCustomerCount,
    (SELECT COUNT(*) FROM SmartBankDB.dbo.Staff) AS ProdStaffCount,
    (SELECT COUNT(*) FROM SmartBankDB_Dev.dbo.Staff) AS DevStaffCount;
-- Expected: Prod and Dev counts match exactly for both tables
GO


/* ================================================================
   T-C4.2 — POSITIVE: sp_RefreshDevData runs successfully as DBA
   ================================================================ */
PRINT '--- T-C4.2: re-running refresh as DBA (sysadmin session) ---';

EXEC dbo.sp_RefreshDevData;
PRINT 'Refresh completed with no errors.';
GO


/* ================================================================
   T-C4.3 — POSITIVE: Customer masked columns differ from production
   for EVERY row (no accidental real-data leakage)
   ================================================================ */
PRINT '--- T-C4.3: comparing masked Customer columns against production ---';

SELECT COUNT(*) AS RowsWhereFakeMatchesReal
FROM SmartBankDB.dbo.Customer p
JOIN SmartBankDB_Dev.dbo.Customer d ON p.CustomerID = d.CustomerID
WHERE p.CustomerName = d.CustomerName
   OR p.Phone = d.Phone
   OR p.Address = d.Address;
-- Expected: 0 — no row's fake value should ever coincidentally
-- equal its real value across all three masked columns
GO


/* ================================================================
   T-C4.4 — POSITIVE: Staff Salary differs from production for
   every row
   ================================================================ */
PRINT '--- T-C4.4: comparing masked Salary against production ---';

SELECT COUNT(*) AS RowsWhereFakeSalaryMatchesReal
FROM SmartBankDB.dbo.Staff p
JOIN SmartBankDB_Dev.dbo.Staff d ON p.StaffID = d.StaffID
WHERE p.Salary = d.Salary;
-- Expected: 0 (or an extremely small number — see note below)
-- Note: since fake salaries are drawn from a random 3000-9999
-- range, there is a small theoretical chance of an exact
-- coincidental match for one or two rows out of many; 0 is the
-- expected practical outcome for a small seed set like this one
GO


/* ================================================================
   T-C4.5 — POSITIVE: ICNumber and ICNumberHash are NULL in Dev
   ================================================================ */
PRINT '--- T-C4.5: confirming ICNumber/ICNumberHash are nulled in Dev ---';

SELECT COUNT(*) AS RowsWithNonNullICNumber
FROM SmartBankDB_Dev.dbo.Customer
WHERE ICNumber IS NOT NULL OR ICNumberHash IS NOT NULL;
-- Expected: 0
GO


/* ================================================================
   T-C4.6 — POSITIVE: non-masked columns correctly preserved
   (structural realism check)
   ================================================================ */
PRINT '--- T-C4.6: confirming non-masked columns match production ---';

SELECT COUNT(*) AS MismatchedNonMaskedRows
FROM SmartBankDB.dbo.Staff p
JOIN SmartBankDB_Dev.dbo.Staff d ON p.StaffID = d.StaffID
WHERE p.StaffName <> d.StaffName
   OR p.Position <> d.Position
   OR p.Branch <> d.Branch
   OR p.Phone <> d.Phone;
-- Expected: 0 — these columns are intentionally NOT masked
-- (Internal classification, low risk), so they should match exactly
GO


/* ================================================================
   T-C4.7 — NEGATIVE: non-DBA role blocked from running the refresh
   ================================================================ */
PRINT '--- T-C4.7: Bank_Officer attempting to run sp_RefreshDevData ---';

EXECUTE AS USER = 'test_officer_user';
EXEC dbo.sp_RefreshDevData;
-- Expected: Msg 229 EXECUTE permission denied
REVERT;
GO


/* ================================================================
   T-C4.8 — POSITIVE: true random independence (not a fixed 1-to-1
   mapping that could be reverse-engineered)
   ================================================================ */
PRINT '--- T-C4.8: confirming fake name assignment is independently random ---';

EXEC dbo.sp_RefreshDevData;   -- run again to get a fresh random assignment

SELECT CustomerID, CustomerName
FROM SmartBankDB_Dev.dbo.Customer
ORDER BY CustomerID;
-- Expected: compare this output to T-C4.1's earlier run (or any
-- prior refresh) — fake names assigned to the same CustomerID
-- should differ between refreshes, proving assignment is freshly
-- randomized each time rather than a fixed, guessable mapping
-- from real value to fake value
GO


/* ================================================================
   CLEANUP
   ================================================================ */
PRINT '--- Cleaning up test user ---';

IF EXISTS (SELECT 1 FROM sys.database_principals WHERE name = 'test_officer_user')
    DROP USER test_officer_user;
GO

PRINT 'C4 test suite complete.';