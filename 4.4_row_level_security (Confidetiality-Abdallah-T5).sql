USE SmartBankDB;
GO

-- ================================================================
-- TASK #5: ROW-LEVEL SECURITY VIA SESSION_CONTEXT
-- (Not a separate policy object -- this alters the 4 "Own" views
-- already built in Task #4, adding the actual per-person filter.)
-- ================================================================

-- ================================================================
-- Component: Fix a Task #1 gap -- nobody could actually call
-- sp_Login until now. Granted to PUBLIC since a user needs to be
-- able to log in before they belong to any role at all.
-- ================================================================
GRANT EXECUTE ON dbo.sp_Login    TO PUBLIC;
GRANT EXECUTE ON dbo.sp_Logout   TO PUBLIC;
GO


-- ================================================================
-- Component: ALTER vw_StaffOwnRecord
-- (DBA/Manager/Officer only see their OWN staff row now)
-- ================================================================
CREATE OR ALTER VIEW dbo.vw_StaffOwnRecord AS
    SELECT StaffID, StaffName, Position, Branch, Phone, Salary, IsActive
    FROM dbo.Staff
    WHERE StaffID = CAST(SESSION_CONTEXT(N'StaffID') AS INT);
GO


-- ================================================================
-- Component: ALTER vw_AccountOwn
-- (Customer only sees accounts matching their own CustomerID)
-- ================================================================
CREATE OR ALTER VIEW dbo.vw_AccountOwn AS
    SELECT AccountID, CustomerID, AccountType, Balance, IsActive
    FROM dbo.Account
    WHERE CustomerID = CAST(SESSION_CONTEXT(N'CustomerID') AS INT);
GO


-- ================================================================
-- Component: ALTER vw_TransactionOwn
-- ================================================================
CREATE OR ALTER VIEW dbo.vw_TransactionOwn AS
    SELECT
        t.TransID, t.AccountID, t.ToAccountID, t.TransDate,
        t.Amount, t.TransactionType, a.CustomerID
    FROM dbo.TransactionRecord t
    JOIN dbo.Account a ON t.AccountID = a.AccountID
    WHERE a.CustomerID = CAST(SESSION_CONTEXT(N'CustomerID') AS INT);
GO


-- ================================================================
-- Component: ALTER vw_PendingApprovalOwn
-- ================================================================
CREATE OR ALTER VIEW dbo.vw_PendingApprovalOwn AS
    SELECT
        p.RequestID, p.AccountID, p.RequestedBy, p.ApprovedBy, p.Amount,
        p.TransactionType, p.ToAccountID, p.Status, p.RequestDate,
        p.ApprovalDate, a.CustomerID
    FROM dbo.PendingApproval p
    JOIN dbo.Account a ON p.AccountID = a.AccountID
    WHERE a.CustomerID = CAST(SESSION_CONTEXT(N'CustomerID') AS INT);
GO


-- ================================================================
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