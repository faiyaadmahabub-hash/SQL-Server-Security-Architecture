USE SmartBankDB;
GO

-- ================================================================
-- TASK #4: BUILD THE 14 VIEWS (+ 1 direct AuditLog grant)
-- Fixes Weakness 2 (no roles/least-privilege) by making sure each
-- role only ever queries a purpose-built view, never a base table.
-- ================================================================


-- ================================================================
-- GROUP A: Staff-related views
-- ================================================================

-- Component: vw_StaffDirectory
-- (Column-restricted -- ONLY StaffName + Phone, visible to everyone)
CREATE OR ALTER VIEW dbo.vw_StaffDirectory AS
    SELECT StaffName, Phone
    FROM dbo.Staff
    WHERE IsActive = 1;
GO
GRANT SELECT ON dbo.vw_StaffDirectory TO DBA, Bank_Manager, Bank_Officer, Customer;
GO

-- Component: vw_StaffOwnRecord
-- (Built as a plain full-row view for now -- per-person filtering
-- to "only the logged-in staff member" is deferred to Task #5's
-- Row-Level Security policy, not hardcoded here. See decision above.)
CREATE OR ALTER VIEW dbo.vw_StaffOwnRecord AS
    SELECT StaffID, StaffName, Position, Branch, Phone, Salary, IsActive
    FROM dbo.Staff;
GO
GRANT SELECT ON dbo.vw_StaffOwnRecord TO DBA, Bank_Manager, Bank_Officer;
GO

-- Component: vw_AllBankOfficers
-- (Filters by Position -- this IS a role-based filter, not a
-- per-person filter, so it belongs here in Task #4, not Task #5)
CREATE OR ALTER VIEW dbo.vw_AllBankOfficers AS
    SELECT StaffID, StaffName, Position, Branch, Phone, Salary, IsActive
    FROM dbo.Staff
    WHERE Position = 'Bank Officer';
GO
GRANT SELECT ON dbo.vw_AllBankOfficers TO Bank_Manager;
GO


-- ================================================================
-- GROUP B: Customer + Account views
-- ================================================================

-- Component: vw_CustomerAll
CREATE OR ALTER VIEW dbo.vw_CustomerAll AS
    SELECT CustomerID, CustomerName, ICNumber, Phone, Address, IsActive
    FROM dbo.Customer;
GO
GRANT SELECT ON dbo.vw_CustomerAll TO Bank_Manager, Bank_Officer;
GO

-- Component: vw_AccountAll
CREATE OR ALTER VIEW dbo.vw_AccountAll AS
    SELECT AccountID, CustomerID, AccountType, Balance, IsActive
    FROM dbo.Account;
GO
GRANT SELECT ON dbo.vw_AccountAll TO Bank_Manager, Bank_Officer;
GO

-- Component: vw_AccountOwn
-- (Plain view for now -- filtering to "own accounts only" comes
-- from Task #5's Row-Level Security policy, not from this view)
CREATE OR ALTER VIEW dbo.vw_AccountOwn AS
    SELECT AccountID, CustomerID, AccountType, Balance, IsActive
    FROM dbo.Account;
GO
GRANT SELECT ON dbo.vw_AccountOwn TO Customer;
GO


-- ================================================================
-- GROUP C: Transaction views
-- ================================================================

-- Component: vw_TransactionAll
CREATE OR ALTER VIEW dbo.vw_TransactionAll AS
    SELECT TransID, AccountID, ToAccountID, TransDate, Amount, TransactionType
    FROM dbo.TransactionRecord;
GO
GRANT SELECT ON dbo.vw_TransactionAll TO Bank_Manager, Bank_Officer;
GO

-- Component: vw_TransactionOwn
-- (Joins through Account since TransactionRecord has no CustomerID
-- of its own -- plain view for now, RLS policy filters it in Task #5)
CREATE OR ALTER VIEW dbo.vw_TransactionOwn AS
    SELECT
        t.TransID, t.AccountID, t.ToAccountID, t.TransDate,
        t.Amount, t.TransactionType,
        a.CustomerID  -- needed here so Task #5's RLS policy has
                       -- something to filter on
    FROM dbo.TransactionRecord t
    JOIN dbo.Account a ON t.AccountID = a.AccountID;
GO
GRANT SELECT ON dbo.vw_TransactionOwn TO Customer;
GO


-- ================================================================
-- GROUP D: PendingApproval views
-- ================================================================

-- Component: vw_PendingApprovalAll
-- (Column names corrected to match A's actual table: RequestID,
-- RequestedBy, ApprovedBy, ToAccountID, RequestDate, ApprovalDate)
CREATE OR ALTER VIEW dbo.vw_PendingApprovalAll AS
    SELECT RequestID, AccountID, RequestedBy, ApprovedBy, Amount,
           TransactionType, ToAccountID, Status, RequestDate, ApprovalDate
    FROM dbo.PendingApproval;
GO
GRANT SELECT ON dbo.vw_PendingApprovalAll TO Bank_Manager;
GO

-- Component: vw_PendingApprovalOwn
-- (Same join-through-Account pattern as vw_TransactionOwn)
CREATE OR ALTER VIEW dbo.vw_PendingApprovalOwn AS
    SELECT
        p.RequestID, p.AccountID, p.RequestedBy, p.ApprovedBy, p.Amount,
        p.TransactionType, p.ToAccountID, p.Status, p.RequestDate, p.ApprovalDate,
        a.CustomerID
    FROM dbo.PendingApproval p
    JOIN dbo.Account a ON p.AccountID = a.AccountID;
GO
GRANT SELECT ON dbo.vw_PendingApprovalOwn TO Customer;
GO


-- ================================================================
-- GROUP E: Audit + History access
-- ================================================================

-- Component: AuditLog direct grant
-- (Not a view -- AuditLog isn't one of the 5 restricted business
-- tables from Task #3, so a direct GRANT is correct here)
GRANT SELECT ON dbo.AuditLog TO DBA, Bank_Manager;
GO

-- Component: vw_Staff_History
-- (Column names corrected to match A's actual hidden period
-- columns: SysStartTime, SysEndTime -- not ValidFrom/ValidTo)
CREATE OR ALTER VIEW dbo.vw_Staff_History AS
    SELECT StaffID, StaffName, Position, Branch, Phone, Salary,
           SysStartTime, SysEndTime
    FROM dbo.Staff FOR SYSTEM_TIME ALL;
GO
GRANT SELECT ON dbo.vw_Staff_History TO DBA;
GO

-- Component: vw_Customer_History
CREATE OR ALTER VIEW dbo.vw_Customer_History AS
    SELECT CustomerID, CustomerName, ICNumber, Phone, Address,
           SysStartTime, SysEndTime
    FROM dbo.Customer FOR SYSTEM_TIME ALL;
GO
GRANT SELECT ON dbo.vw_Customer_History TO DBA;
GO

-- Component: vw_Account_History
CREATE OR ALTER VIEW dbo.vw_Account_History AS
    SELECT AccountID, CustomerID, AccountType, Balance,
           SysStartTime, SysEndTime
    FROM dbo.Account FOR SYSTEM_TIME ALL;
GO
GRANT SELECT ON dbo.vw_Account_History TO DBA;
GO

-- Component: vw_TransactionRecord_History
CREATE OR ALTER VIEW dbo.vw_TransactionRecord_History AS
    SELECT TransID, AccountID, ToAccountID, TransDate, Amount,
           TransactionType, SysStartTime, SysEndTime
    FROM dbo.TransactionRecord FOR SYSTEM_TIME ALL;
GO
GRANT SELECT ON dbo.vw_TransactionRecord_History TO DBA;
GO


-- ================================================================
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
SELECT * FROM dbo.AuditLog;
REVERT;
-- Expected: succeeds

-- TEST 13: Officer is BLOCKED from AuditLog (negative)
EXECUTE AS USER = 'test_officer_user';
SELECT * FROM dbo.AuditLog;
REVERT;
-- Expected: permission denied error

-- TEST 14: DBA can read Staff history (positive)
EXECUTE AS USER = 'test_dba_user';
SELECT * FROM dbo.vw_Staff_History;
REVERT;
-- Expected: succeeds, shows current + historical rows

-- TEST 15: Manager is BLOCKED from Staff history (negative --
-- history is DBA-only)
EXECUTE AS USER = 'test_manager_user';
SELECT * FROM dbo.vw_Staff_History;
REVERT;
-- Expected: permission denied error