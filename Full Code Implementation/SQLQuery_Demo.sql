-- ================================================================
-- SmartBankDB -- LIVE DEMO WALKTHROUGH  (v2, logon-trigger workflow)
-- ================================================================
-- The Codebase.sql Part 11 logon trigger populates SESSION_CONTEXT
-- automatically the instant a connection is opened. No sp_Login call
-- needed. Every RLS 'Own' view returns the right rows straight after
-- SQL Authentication succeeds.
--
-- =========================
-- HOW TO SET UP FOR DEMO DAY
-- =========================
-- Open FIVE SSMS query windows before starting. Each window uses a
-- different login on Object Explorer -> Connect -> Database Engine:
--
--   Tab A (Admin):    Windows Authentication as FAIYAAD\<you>
--                     -> use for catalog queries, native audit reads,
--                        backup/recovery, and DELETE simulations
--   Tab B (Manager):  SQL Auth  SmartBank_Manager1   / Manager1P@ss!
--   Tab C (Officer):  SQL Auth  SmartBank_Officer1   / Officer1P@ss!
--   Tab D (Customer): SQL Auth  SmartBank_Customer1 / Customer1P@ss!
--   Tab E (Customer): SQL Auth  SmartBank_Customer2 / Customer2P@ss!
--
-- Every block below is prefixed with "-- TAB X:" telling you which
-- window to run it in. Running a block in the wrong tab will either
-- error (permission denied) or return wrong data.
--
-- To confirm the trigger populated context in any tab, run once at start:
--   SELECT CAST(SESSION_CONTEXT(N'UserType')   AS NVARCHAR(20)) AS UserType,
--          CAST(SESSION_CONTEXT(N'StaffID')    AS INT)          AS StaffID,
--          CAST(SESSION_CONTEXT(N'CustomerID') AS INT)          AS CustomerID;
-- If all three columns are NULL, the trigger didn't fire -- see Appendix B.
-- ================================================================

USE SmartBankDB;
GO


-- ================================================================
-- REQUIREMENT 1: LOGIN AS A FEW DIFFERENT USERS
-- ================================================================
-- "Logging in" IS the SSMS connection. Nothing to run other than
-- proving the trigger set context correctly per tab.
-- ================================================================

-- ---------- 1.1 Manager tab verification ----------
-- TAB B (Manager)
SELECT
    SUSER_SNAME()                                       AS NativeLogin,
    CAST(SESSION_CONTEXT(N'UserType') AS NVARCHAR(20))  AS UserType,
    CAST(SESSION_CONTEXT(N'StaffID')  AS INT)           AS StaffID;
GO

-- ---------- 1.2 DBA tab verification ----------
-- TAB opened separately as SQL Auth: SmartBank_DBA1 / Dba1P@ss!
SELECT
    SUSER_SNAME()                                       AS NativeLogin,
    CAST(SESSION_CONTEXT(N'UserType') AS NVARCHAR(20))  AS UserType,
    CAST(SESSION_CONTEXT(N'StaffID')  AS INT)           AS StaffID;
GO

-- ---------- 1.3 Officer tab verification ----------
-- TAB C (Officer)
SELECT
    SUSER_SNAME()                                       AS NativeLogin,
    CAST(SESSION_CONTEXT(N'UserType') AS NVARCHAR(20))  AS UserType,
    CAST(SESSION_CONTEXT(N'StaffID')  AS INT)           AS StaffID;
GO

-- ---------- 1.4 Customer tab verification ----------
-- TAB D (Customer 1)
SELECT
    SUSER_SNAME()                                       AS NativeLogin,
    CAST(SESSION_CONTEXT(N'UserType')   AS NVARCHAR(20)) AS UserType,
    CAST(SESSION_CONTEXT(N'CustomerID') AS INT)          AS CustomerID;
GO

-- ---------- 1.5 Failed login demo -- APP-SIDE (AuditSchema.AuditLog) ----------
-- TAB A (Admin) -- proves sp_Login writes REJECTED row on wrong password
DECLARE @LoginSuccess BIT, @PasswordExpired BIT, @LoginMessage NVARCHAR(200);
EXEC dbo.sp_Login N'SmartBank_Customer1', N'wrong_password',
                  @LoginSuccess OUTPUT, @PasswordExpired OUTPUT, @LoginMessage OUTPUT;
SELECT @LoginSuccess AS Success, @LoginMessage AS Message;
GO

-- ---------- 1.6 Failed login demo -- NATIVE (LGIF in C:\SQLAudit\) ----------
-- Perform this LIVE, not through code, to generate a real LGIF event:
--   1. In SSMS, click Object Explorer's Connect button -> Database Engine
--   2. Authentication = SQL Server Authentication
--   3. Login = SmartBank_Customer2
--   4. Password = deliberately_wrong_password
--   5. Click Connect -> SSMS shows "Login failed" error, dismiss it
--   6. That single click generated one LGIF row in the native audit file.
--
-- To verify it landed, run Section 4.8 -- the LGIF row will be there,
-- attributed to SmartBank_Customer2, with succeeded = false.
--
-- Why both 1.5 and 1.6: sp_Login (1.5) protects against application-layer
-- brute-force (locks the UserLogin account); SQL Server's native LGIF
-- (1.6) catches brute-force against the connection itself. They're
-- complementary and both audited in their own trails.


-- ================================================================
-- REQUIREMENT 2: USERS AND PERMISSION SETTINGS FOR EACH ROLE
-- ================================================================

-- ---------- 2.1 Roles and their members ----------
-- TAB A (Admin)
SELECT
    r.name                        AS RoleName,
    m.name                        AS MemberName,
    m.type_desc                   AS MemberType,
    CASE WHEN l.is_disabled = 1 THEN 'DISABLED' ELSE 'ACTIVE' END AS LoginStatus
FROM sys.database_role_members drm
JOIN sys.database_principals r ON r.principal_id = drm.role_principal_id
JOIN sys.database_principals m ON m.principal_id = drm.member_principal_id
LEFT JOIN sys.sql_logins l     ON l.name        = m.name
WHERE r.name IN ('DBA', 'Bank_Manager', 'Bank_Officer', 'Customer', 'RecoveryAdmin')
ORDER BY r.name, m.name;
GO

-- ---------- 2.2 The 5 test identities (application-level, in UserLogin) ----------
-- TAB A (Admin)
SELECT
    ul.Username, ul.UserType, ul.IsActive,
    s.StaffName, s.Position, s.Branch,
    c.CustomerName
FROM dbo.UserLogin ul
LEFT JOIN dbo.Staff    s ON s.StaffID    = ul.StaffID
LEFT JOIN dbo.Customer c ON c.CustomerID = ul.CustomerID
WHERE ul.Username LIKE 'SmartBank_%'
ORDER BY ul.UserType, ul.Username;
GO

-- ---------- 2.3 Object-level permissions by role ----------
-- TAB A (Admin)
SELECT
    dp.name                                                          AS RoleName,
    perm.class_desc,
    ISNULL(OBJECT_SCHEMA_NAME(perm.major_id), '')                    AS SchemaName,
    ISNULL(OBJECT_NAME(perm.major_id), '')                           AS ObjectName,
    perm.permission_name,
    perm.state_desc                                                  AS GrantState
FROM sys.database_permissions perm
JOIN sys.database_principals dp ON dp.principal_id = perm.grantee_principal_id
WHERE dp.name IN ('DBA', 'Bank_Manager', 'Bank_Officer', 'Customer', 'RecoveryAdmin')
  AND perm.class_desc IN ('OBJECT_OR_COLUMN', 'SCHEMA')
ORDER BY dp.name, GrantState, ObjectName, permission_name;
GO

-- ---------- 2.4 UNMASK grants (proves the least-privilege DDM policy) ----------
-- TAB A (Admin)
SELECT
    USER_NAME(perm.grantee_principal_id) AS RoleName,
    OBJECT_NAME(perm.major_id)           AS TableName,
    COL_NAME(perm.major_id, perm.minor_id) AS ColumnName,
    perm.permission_name,
    perm.state_desc                      AS GrantState
FROM sys.database_permissions perm
WHERE perm.permission_name = 'UNMASK'
ORDER BY TableName, ColumnName, RoleName;
GO


-- ================================================================
-- REQUIREMENT 3: PROVE PERMISSIONS MEET THE ASSIGNMENT SPEC
-- ================================================================

-- ---------- 3.1 Any authenticated user (customer) can view staff name + contact ----------
-- TAB D (Customer 1)  -- expect: full StaffName + Phone list, IsActive=1 rows only
SELECT * FROM dbo.vw_StaffDirectory;
GO

-- ---------- 3.2 Officer: own record + all customer accounts + all transactions ----------
-- TAB C (Officer)  -- run one at a time so each result is visible on its own
SELECT * FROM dbo.vw_StaffOwnRecord;     -- expect: only Farah Aina's row
GO
SELECT * FROM dbo.vw_AccountAll;         -- expect: every customer's accounts
GO
SELECT * FROM dbo.vw_TransactionAll;     -- expect: every transaction
GO
SELECT * FROM dbo.vw_CustomerAll;        -- expect: every customer
GO

-- ---------- 3.3 Customer: own accounts + own transactions ----------
-- TAB D (Customer 1)
SELECT * FROM dbo.vw_AccountOwn;         -- expect: only cust1's account(s)
GO
SELECT * FROM dbo.vw_TransactionOwn;     -- expect: only cust1's transactions
GO
SELECT * FROM dbo.vw_CustomerOwnProfile; -- expect: only cust1's own profile
GO

-- ---------- 3.4 RLS proof: Customer 2 cannot see Customer 1's data even by ID ----------
-- Step 1: TAB A (Admin) -- look up cust1's AccountID once, paste into Step 2
SELECT AccountID
FROM dbo.Account
WHERE CustomerID = (SELECT CustomerID FROM dbo.UserLogin WHERE Username = 'SmartBank_Customer1');
GO

-- Step 2: TAB E (Customer 2) -- REPLACE 1 with the AccountID from Step 1
-- EXPECT: both queries return 0 rows -- RLS filters cust1's account out for cust2
SELECT * FROM dbo.vw_AccountOwn     WHERE AccountID = 1;
SELECT * FROM dbo.vw_TransactionOwn WHERE AccountID = 1;
GO

-- ---------- 3.5 Direct table access is denied for Officer ----------
-- TAB C (Officer) -- each of these should be DENIED
SELECT * FROM dbo.Staff;                                     -- DENY (blanket DENY on base table)
GO
SELECT * FROM dbo.Customer;                                  -- DENY
GO
UPDATE dbo.Staff SET Salary = 999999 WHERE StaffID = 1;      -- DENY
GO
DELETE FROM dbo.TransactionRecord;                           -- DENY
GO
CREATE TABLE dbo.Officer_Test_Table (ID INT);                -- DENY (DDL is DBA-only)
GO

-- ---------- 3.6 Staff self-update: Officer updates their own Phone ----------
-- TAB C (Officer)
SELECT StaffID, StaffName, Phone FROM dbo.vw_StaffOwnRecord;   -- before
GO

DECLARE @UpdateSuccess BIT, @UpdateMessage NVARCHAR(200);
EXEC dbo.sp_UpdateOwnStaffRecord
    @Phone   = N'0139999999',
    @Success = @UpdateSuccess OUTPUT,
    @Message = @UpdateMessage OUTPUT;
SELECT @UpdateSuccess AS Success, @UpdateMessage AS Message;
GO

SELECT StaffID, StaffName, Phone FROM dbo.vw_StaffOwnRecord;   -- after
GO

-- ---------- 3.7 Manager-only: create a new Bank Officer via sp_ManageStaff ----------
-- TAB B (Manager)
DECLARE @Success BIT, @Message NVARCHAR(200);
EXEC dbo.sp_ManageStaff
    @StaffName = N'Ahmad Faizal',
    @Position  = N'Bank Officer',
    @Branch    = N'PJ Branch',
    @Phone     = N'0111234567',
    @Salary    = 4700.00,
    @Success   = @Success OUTPUT,
    @Message   = @Message OUTPUT;
SELECT @Success AS Success, @Message AS Message;
GO

SELECT * FROM dbo.vw_AllBankOfficers ORDER BY StaffID DESC;
GO

-- ---------- 3.8 Officer cannot call the Manager-only proc ----------
-- TAB C (Officer)  -- EXPECT: permission denied at EXEC time
DECLARE @Success BIT, @Message NVARCHAR(200);
EXEC dbo.sp_ManageStaff
    @StaffName = N'Should Not Exist',
    @Position  = N'Bank Officer',
    @Branch    = N'X',
    @Phone     = N'0100000000',
    @Salary    = 1000,
    @Success   = @Success OUTPUT,
    @Message   = @Message OUTPUT;
GO


-- ================================================================
-- REQUIREMENT 3 (extension): CUSTOMER TRANSACTION WORKFLOW
-- ================================================================
-- Every block below runs in TAB D (Customer 1) unless otherwise noted.
-- vw_AccountOwn lets Customer see their own AccountID(s) -- much cleaner
-- than the old pattern of pre-fetching from dbo.Account as dbo.
-- ================================================================

-- ---------- 3.9 Customer 1 deposits RM50 into their own account ----------
-- TAB D (Customer 1)
DECLARE @MyAccountID INT = (SELECT TOP 1 AccountID FROM dbo.vw_AccountOwn);

DECLARE @Success BIT, @Message NVARCHAR(200);
EXEC dbo.sp_ProcessTransaction
    @AccountID       = @MyAccountID,
    @TransactionType = N'Deposit',
    @Amount          = 50.00,
    @Success         = @Success OUTPUT,
    @Message         = @Message OUTPUT;
SELECT @Success AS Success, @Message AS Message;

SELECT AccountID, Balance FROM dbo.vw_AccountOwn WHERE AccountID = @MyAccountID;
GO

-- ---------- 3.10 Customer 1 withdraws RM20 from their own account ----------
-- TAB D (Customer 1)
DECLARE @MyAccountID INT = (SELECT TOP 1 AccountID FROM dbo.vw_AccountOwn);

DECLARE @Success BIT, @Message NVARCHAR(200);
EXEC dbo.sp_ProcessTransaction
    @AccountID       = @MyAccountID,
    @TransactionType = N'Withdrawal',
    @Amount          = 20.00,
    @Success         = @Success OUTPUT,
    @Message         = @Message OUTPUT;
SELECT @Success AS Success, @Message AS Message;

SELECT AccountID, Balance FROM dbo.vw_AccountOwn WHERE AccountID = @MyAccountID;
GO

-- ---------- 3.11 Customer 1 tries to withdraw from Customer 2's account (DENIED) ----------
-- Step 1: TAB A (Admin) -- get cust2's AccountID
SELECT AccountID FROM dbo.Account
WHERE CustomerID = (SELECT CustomerID FROM dbo.UserLogin WHERE Username = 'SmartBank_Customer2');
GO

-- Step 2: TAB D (Customer 1) -- REPLACE 2 with cust2's AccountID from Step 1
-- EXPECT: Success = 0, message says "not the account owner" or similar
DECLARE @Success BIT, @Message NVARCHAR(200);
EXEC dbo.sp_ProcessTransaction
    @AccountID       = 2,                   -- <-- someone else's account
    @TransactionType = N'Withdrawal',
    @Amount          = 10.00,
    @Success         = @Success OUTPUT,
    @Message         = @Message OUTPUT;
SELECT @Success AS Success, @Message AS Message;
GO

-- ---------- 3.12 Customer 1 tries an overdraft withdrawal (DENIED) ----------
-- TAB D (Customer 1)  -- EXPECT: Success = 0, "insufficient funds"
DECLARE @MyAccountID INT = (SELECT TOP 1 AccountID FROM dbo.vw_AccountOwn);

DECLARE @Success BIT, @Message NVARCHAR(200);
EXEC dbo.sp_ProcessTransaction
    @AccountID       = @MyAccountID,
    @TransactionType = N'Withdrawal',
    @Amount          = 999999999.00,
    @Success         = @Success OUTPUT,
    @Message         = @Message OUTPUT;
SELECT @Success AS Success, @Message AS Message;
GO

-- ---------- 3.13 Customer 1 tries a negative deposit (DENIED) ----------
-- TAB D (Customer 1)  -- EXPECT: Success = 0, "invalid amount"
DECLARE @MyAccountID INT = (SELECT TOP 1 AccountID FROM dbo.vw_AccountOwn);

DECLARE @Success BIT, @Message NVARCHAR(200);
EXEC dbo.sp_ProcessTransaction
    @AccountID       = @MyAccountID,
    @TransactionType = N'Deposit',
    @Amount          = -50.00,
    @Success         = @Success OUTPUT,
    @Message         = @Message OUTPUT;
SELECT @Success AS Success, @Message AS Message;
GO

-- ---------- 3.14 Officer tries sp_ProcessTransaction (DENIED - wrong role) ----------
-- Step 1: TAB A (Admin) -- get a customer AccountID
SELECT TOP 1 AccountID FROM dbo.Account WHERE CustomerID IS NOT NULL;
GO

-- Step 2: TAB C (Officer) -- REPLACE 1 with the AccountID from Step 1
-- EXPECT: permission denied on EXEC (Bank_Officer has no grant on this proc)
DECLARE @Success BIT, @Message NVARCHAR(200);
EXEC dbo.sp_ProcessTransaction
    @AccountID       = 1,
    @TransactionType = N'Deposit',
    @Amount          = 10.00,
    @Success         = @Success OUTPUT,
    @Message         = @Message OUTPUT;
GO

-- ---------- 3.15 Customer 1 deposits RM15,000 (over threshold -> Manager approval) ----------
-- TAB D (Customer 1)  -- EXPECT: Success = 1, "routed for Manager approval"
DECLARE @MyAccountID INT = (SELECT TOP 1 AccountID FROM dbo.vw_AccountOwn);

DECLARE @Success BIT, @Message NVARCHAR(200);
EXEC dbo.sp_ProcessTransaction
    @AccountID       = @MyAccountID,
    @TransactionType = N'Deposit',
    @Amount          = 15000.00,
    @Success         = @Success OUTPUT,
    @Message         = @Message OUTPUT;
SELECT @Success AS Success, @Message AS Message;

-- Confirm balance has NOT moved yet
SELECT AccountID, Balance FROM dbo.vw_AccountOwn WHERE AccountID = @MyAccountID;
GO

-- ---------- 3.16 Manager approves the pending RM15,000 request ----------
-- TAB B (Manager)
SELECT * FROM dbo.vw_PendingApprovalAll WHERE Status = 'Pending' ORDER BY RequestID DESC;
GO

-- Pick the most recent pending request (adjust WHERE if needed)
DECLARE @RequestID INT = (
    SELECT TOP 1 RequestID
    FROM dbo.vw_PendingApprovalAll
    WHERE Status = 'Pending'
    ORDER BY RequestID DESC
);

DECLARE @Success BIT, @Message NVARCHAR(200);
EXEC dbo.sp_ApproveTransaction
    @RequestID = @RequestID,
    @Approve   = 1,
    @Success   = @Success OUTPUT,
    @Message   = @Message OUTPUT;
SELECT @Success AS Success, @Message AS Message;

-- Confirm: request is Approved AND balance moved
SELECT * FROM dbo.vw_PendingApprovalAll WHERE RequestID = @RequestID;
GO

-- ---------- 3.17 Customer 1 transfers RM200 to Customer 2 ----------
-- Step 1: TAB A (Admin) -- get cust2's AccountID
SELECT AccountID FROM dbo.Account
WHERE CustomerID = (SELECT CustomerID FROM dbo.UserLogin WHERE Username = 'SmartBank_Customer2');
GO

-- Step 2: TAB D (Customer 1) -- REPLACE 2 with cust2's AccountID from Step 1
DECLARE @MyAccountID   INT = (SELECT TOP 1 AccountID FROM dbo.vw_AccountOwn);
DECLARE @ToAccountID   INT = 2;

DECLARE @Success BIT, @Message NVARCHAR(200);
EXEC dbo.sp_ProcessTransaction
    @AccountID       = @MyAccountID,
    @TransactionType = N'Transfer',
    @Amount          = 200.00,
    @ToAccountID     = @ToAccountID,
    @Success         = @Success OUTPUT,
    @Message         = @Message OUTPUT;
SELECT @Success AS Success, @Message AS Message;

SELECT AccountID, Balance FROM dbo.vw_AccountOwn WHERE AccountID = @MyAccountID;
GO

-- ---------- 3.18 Manager UPDATES an existing Officer via sp_ManageStaff ----------
-- TAB B (Manager)
-- StaffID = 3 is Farah Aina (Bank Officer) from the seed data.
SELECT StaffID, StaffName, Position, Branch, Phone, Salary
FROM dbo.vw_AllBankOfficers
WHERE StaffID = 3;
GO

DECLARE @Success BIT, @Message NVARCHAR(200);
EXEC dbo.sp_ManageStaff
    @StaffID   = 3,                     -- <-- update mode
    @StaffName = N'Farah Aina',
    @Position  = N'Bank Officer',
    @Branch    = N'Ampang Branch',
    @Phone     = N'0138888888',
    @Salary    = 4700.00,
    @Success   = @Success OUTPUT,
    @Message   = @Message OUTPUT;
SELECT @Success AS Success, @Message AS Message;

SELECT StaffID, StaffName, Position, Branch, Phone, Salary
FROM dbo.vw_AllBankOfficers
WHERE StaffID = 3;
GO

-- ---------- 3.19 Manager CANNOT update a non-Officer record via sp_ManageStaff ----------
-- TAB B (Manager)
-- StaffID = 2 is the DBA (Nabil Hakim). EXPECT: Success = 0, rejected.
DECLARE @Success BIT, @Message NVARCHAR(200);
EXEC dbo.sp_ManageStaff
    @StaffID   = 2,
    @StaffName = N'Nabil Hakim',
    @Position  = N'Bank Officer',
    @Branch    = N'HQ',
    @Phone     = N'0999999999',
    @Salary    = 99999.00,
    @Success   = @Success OUTPUT,
    @Message   = @Message OUTPUT;
SELECT @Success AS Success, @Message AS Message;
GO

-- Prove the DBA row was NOT modified (TAB A -- Admin has full read access)
-- Run this in TAB A:
--    SELECT StaffID, StaffName, Position, Phone FROM dbo.Staff WHERE StaffID = 2;

-- ---------- 3.20 Officer CANNOT delete a Customer record ----------
-- TAB C (Officer)  -- both DELETEs should be DENIED
DELETE FROM dbo.Customer      WHERE CustomerID = 1;
GO
DELETE FROM dbo.vw_CustomerAll WHERE CustomerID = 1;
GO

-- ---------- 3.21 Officer creates + updates a Customer via sp_ManageCustomer ----------
-- TAB C (Officer)
DECLARE @Success BIT, @Message NVARCHAR(200);
EXEC dbo.sp_ManageCustomer
    @CustomerName = N'Demo NewCustomer',
    @ICNumber     = N'880808080808',
    @Phone        = N'0155555555',
    @Address      = N'Demo Address, KL',
    @Success      = @Success OUTPUT,
    @Message      = @Message OUTPUT;
SELECT @Success AS Success, @Message AS Message;
GO

DECLARE @NewCustomerID INT = (
    SELECT CustomerID FROM dbo.vw_CustomerAll WHERE CustomerName = N'Demo NewCustomer'
);

DECLARE @Success2 BIT, @Message2 NVARCHAR(200);
EXEC dbo.sp_ManageCustomer
    @CustomerID   = @NewCustomerID,
    @CustomerName = N'Demo NewCustomer',
    @Phone        = N'0166666666',
    @Address      = N'New Demo Address, PJ',
    @Success      = @Success2 OUTPUT,
    @Message      = @Message2 OUTPUT;
SELECT @Success2 AS Success, @Message2 AS Message;

SELECT CustomerID, CustomerName, Phone, Address
FROM dbo.vw_CustomerAll WHERE CustomerID = @NewCustomerID;
GO

-- ---------- 3.22 Officer opens an Account for a Customer via sp_ManageAccount ----------
-- TAB C (Officer)
DECLARE @TargetCustomerID INT = (
    SELECT CustomerID FROM dbo.vw_CustomerAll WHERE CustomerName = N'Demo NewCustomer'
);

DECLARE @Success BIT, @Message NVARCHAR(200);
EXEC dbo.sp_ManageAccount
    @CustomerID  = @TargetCustomerID,
    @AccountType = N'Savings',
    @Success     = @Success OUTPUT,
    @Message     = @Message OUTPUT;
SELECT @Success AS Success, @Message AS Message;

SELECT AccountID, CustomerID, AccountType, Balance
FROM dbo.vw_AccountAll WHERE CustomerID = @TargetCustomerID;
GO

-- ---------- 3.23 Manager REJECTS a pending approval (@Approve = 0) ----------
-- Step 1: TAB E (Customer 2) -- create a fresh pending request
DECLARE @MyAccountID INT = (SELECT TOP 1 AccountID FROM dbo.vw_AccountOwn);

DECLARE @Success BIT, @Message NVARCHAR(200);
EXEC dbo.sp_ProcessTransaction
    @AccountID       = @MyAccountID,
    @TransactionType = N'Deposit',
    @Amount          = 12000.00,             -- above RM10,000 -> pending
    @Success         = @Success OUTPUT,
    @Message         = @Message OUTPUT;
SELECT @Success AS Success, @Message AS Message;
GO

-- Step 2: TAB B (Manager) -- reject the most recent pending request
DECLARE @RequestID INT = (
    SELECT TOP 1 RequestID FROM dbo.vw_PendingApprovalAll
    WHERE Status = 'Pending' ORDER BY RequestID DESC
);

DECLARE @Success BIT, @Message NVARCHAR(200);
EXEC dbo.sp_ApproveTransaction
    @RequestID = @RequestID,
    @Approve   = 0,                          -- <-- reject
    @Success   = @Success OUTPUT,
    @Message   = @Message OUTPUT;
SELECT @Success AS Success, @Message AS Message;

SELECT * FROM dbo.vw_PendingApprovalAll WHERE RequestID = @RequestID;
GO

-- ---------- 3.24 DBA CANNOT read or write customer business data ----------
-- TAB opened separately as SQL Auth: SmartBank_DBA1 / Dba1P@ss!
SELECT * FROM dbo.Customer;                        -- DENY: business data
GO
SELECT * FROM dbo.vw_CustomerAll;                  -- DENY
GO
SELECT * FROM dbo.Account;                         -- DENY
GO
UPDATE dbo.Account SET Balance = 999999;           -- DENY: no data-write rights
GO
DELETE FROM dbo.TransactionRecord;                 -- DENY
GO
-- But DBA CAN do DDL
CREATE TABLE dbo.DBA_Test_Table (ID INT);          -- ALLOW
GO
DROP   TABLE dbo.DBA_Test_Table;                   -- ALLOW
GO

-- ---------- 3.25 RLS proof: Officer1 and Officer2 each see ONLY their own staff record ----------
-- Strongest available RLS proof -- two identities in the SAME role (Bank_Officer)
-- both query the same view and get different single rows back.

-- Step 1: TAB C (Officer1 = Farah Aina)  -- EXPECT: one row, StaffName = 'Farah Aina'
SELECT StaffID, StaffName, Position, Branch FROM dbo.vw_StaffOwnRecord;
GO

-- Step 2: TAB opened separately as SQL Auth: SmartBank_Officer2 / Officer2P@ss!
-- EXPECT: one row, StaffName = 'Ahmad Faizal' -- proves same-role isolation
SELECT StaffID, StaffName, Position, Branch FROM dbo.vw_StaffOwnRecord;
GO

-- ---------- 3.26 Two Managers have identical permissions (role, not identity, drives access) ----------
-- Manager2 (Rashid Karim) should have the same visibility as Manager1 (Aiman Zulkifli):
-- all bank officers, all customers, pending approvals. Not because they're the same person,
-- but because they're both in the Bank_Manager role.

-- Step 1: TAB B (Manager1)  -- capture what Manager1 sees
SELECT COUNT(*) AS OfficersSeen FROM dbo.vw_AllBankOfficers;
GO
SELECT COUNT(*) AS CustomersSeen FROM dbo.vw_CustomerAll;
GO

-- Step 2: TAB opened separately as SQL Auth: SmartBank_Manager2 / Manager2P@ss!
-- EXPECT: identical counts to Manager1
SELECT COUNT(*) AS OfficersSeen FROM dbo.vw_AllBankOfficers;
GO
SELECT COUNT(*) AS CustomersSeen FROM dbo.vw_CustomerAll;
GO

-- Manager2 also sees their OWN record only, same RLS as Manager1
SELECT StaffID, StaffName FROM dbo.vw_StaffOwnRecord;  -- EXPECT: Rashid Karim
GO


-- ================================================================
-- REQUIREMENT 4: SHOW AUDIT RECORDS FOR STEPS 1 AND 3
-- ================================================================
-- IMPORTANT: With the logon trigger populating context automatically,
-- successful "logins" no longer go through sp_Login -- they go through
-- the trigger. Consequences for the audit trail:
--   * Successful login events -> ONLY appear in native audit (LGIS in
--     C:\SQLAudit\), NOT in AuditSchema.AuditLog.
--   * Failed sp_Login calls (Section 1.5, wrong password) -> STILL
--     appear in AuditSchema.AuditLog as REJECTED rows.
--   * Native failed logins (SQL Auth wrong password) -> LGIF in native.
--   * DML actions (staff/customer/account changes) -> unchanged, still
--     captured by triggers -> AuditSchema.AuditLog.
-- To prove Requirement 1's logins are audited, native audit (4.5, 4.8,
-- 4.9, 4.10) is now the primary source.
-- ================================================================

-- ---------- 4.1 Custom audit trail: everything from today ----------
-- TAB A (Admin)
SELECT *
FROM AuditSchema.AuditLog
WHERE CAST(ChangeDate AS DATE) = CAST(SYSDATETIME() AS DATE)
ORDER BY ChangeDate DESC;
GO

-- ---------- 4.2 Custom audit trail: just today's staff-table changes ----------
-- TAB A (Admin)
SELECT LogID, ColumnName, RecordID, ActionType, Activity, ChangedBy, ChangeDate
FROM AuditSchema.AuditLog
WHERE TableName = 'Staff'
  AND CAST(ChangeDate AS DATE) = CAST(SYSDATETIME() AS DATE)
ORDER BY ChangeDate DESC;
GO

-- ---------- 4.3 Custom audit trail: just the REJECTED (denied) attempts ----------
-- TAB A (Admin)
SELECT LogID, TableName, RecordID, ChangedBy, Activity, ChangeDate
FROM AuditSchema.AuditLog
WHERE ActionType = 'REJECTED'
ORDER BY ChangeDate DESC;
GO

-- ---------- 4.4 Native SQL Server Audit: is it running? ----------
-- TAB A (Admin)
SELECT name, status_desc FROM sys.dm_server_audit_status;
GO
SELECT name, is_state_enabled FROM sys.server_audits            WHERE name = 'SmartBank_ServerAudit';
GO
SELECT name, is_state_enabled FROM sys.server_audit_specifications   WHERE name = 'SmartBank_LoginAuditSpec';
GO
SELECT name, is_state_enabled FROM sys.database_audit_specifications WHERE name = 'SmartBank_DatabaseAuditSpec';
GO

-- ---------- 4.5 Native audit: login events (Requirement 1 primary proof) ----------
-- TAB opened as SmartBank_DBA1  (proc is wrapped in EXECUTE AS OWNER so DBA can call it)
EXEC dbo.sp_DBA_ViewLoginAudit;
GO

-- ---------- 4.6 Native audit: full raw file (DBA only) ----------
-- TAB opened as SmartBank_DBA1
EXEC dbo.sp_DBA_ViewAuditFile;
GO

-- ---------- 4.7 App-level audit: failed sp_Login attempts + DML from Sec 3 ----------
-- TAB A (Admin)
-- Since successful logins go through the trigger (which doesn't touch
-- dbo.UserLogin.LastLogin), the only "login-related" AuditLog rows are
-- REJECTED attempts from actual sp_Login calls (e.g. Section 1.5).
-- The DML-related rows from Section 3 (staff updates, customer creates,
-- transactions) are all here as INSERT/UPDATE rows.
SELECT
    LogID, ChangeDate, TableName, ColumnName,
    ActionType, RecordID, ChangedBy, Activity
FROM AuditSchema.AuditLog
WHERE ChangeDate >= DATEADD(HOUR, -1, SYSDATETIME())
ORDER BY ChangeDate DESC;
GO

-- ---------- 4.8 Native audit: recent LGIS / LGIF / LGO events ----------
-- TAB opened as SmartBank_DBA1
BEGIN TRY
    SELECT
        event_time,
        action_id,
        CASE action_id
            WHEN 'LGIS' THEN 'Login Success'
            WHEN 'LGIF' THEN 'Login Failed'
            WHEN 'LGO'  THEN 'Logout'
        END AS EventDescription,
        server_principal_name,
        session_server_principal_name,
        succeeded,
        client_ip,
        application_name
    FROM sys.fn_get_audit_file('C:\SQLAudit\*.sqlaudit', DEFAULT, DEFAULT)
    WHERE action_id IN ('LGIS', 'LGIF', 'LGO')
      AND event_time >= DATEADD(HOUR, -1, SYSDATETIME())
    ORDER BY event_time DESC;
END TRY
BEGIN CATCH
    SELECT 'CHECK: audit file may not have flushed yet -- wait a few seconds and re-run.' AS Note,
           ERROR_MESSAGE() AS ErrorMessage;
END CATCH;
GO

-- ---------- 4.9 Per-user login summary from the native audit file ----------
-- TAB opened as SmartBank_DBA1
BEGIN TRY
    SELECT
        server_principal_name AS SqlLogin,
        SUM(CASE WHEN action_id = 'LGIS' THEN 1 ELSE 0 END) AS SuccessfulLogins,
        SUM(CASE WHEN action_id = 'LGIF' THEN 1 ELSE 0 END) AS FailedLogins,
        SUM(CASE WHEN action_id = 'LGO'  THEN 1 ELSE 0 END) AS Logouts,
        MIN(event_time) AS FirstEvent,
        MAX(event_time) AS LastEvent
    FROM sys.fn_get_audit_file('C:\SQLAudit\*.sqlaudit', DEFAULT, DEFAULT)
    WHERE action_id IN ('LGIS', 'LGIF', 'LGO')
      AND event_time >= DATEADD(DAY, -1, SYSDATETIME())
      AND server_principal_name LIKE 'SmartBank_%'
      -- LIKE catches all 8 SmartBank_XxxN identities
    GROUP BY server_principal_name
    ORDER BY server_principal_name;
END TRY
BEGIN CATCH
    SELECT 'CHECK: audit file not readable yet.' AS Note, ERROR_MESSAGE() AS ErrorMessage;
END CATCH;
GO

-- ---------- 4.10 Combined view: native login events + app-level REJECTED today ----------
-- TAB opened as SmartBank_DBA1
BEGIN TRY
    SELECT
        event_time                                     AS EventTime,
        'Native Audit'                                 AS Source,
        CASE action_id
            WHEN 'LGIS' THEN 'Login Success'
            WHEN 'LGIF' THEN 'Login Failed'
            WHEN 'LGO'  THEN 'Logout'
        END                                            AS EventType,
        server_principal_name                          AS Identity,
        CAST(NULL AS NVARCHAR(200))                    AS Detail
    FROM sys.fn_get_audit_file('C:\SQLAudit\*.sqlaudit', DEFAULT, DEFAULT)
    WHERE action_id IN ('LGIS', 'LGIF', 'LGO')
      AND event_time >= CAST(SYSDATETIME() AS DATE)
      AND server_principal_name LIKE 'SmartBank_%'
      -- LIKE catches all 8 SmartBank_XxxN identities

    UNION ALL

    SELECT
        ChangeDate, 'App Audit',
        CASE WHEN ActionType = 'REJECTED' THEN 'sp_Login Failed' ELSE ActionType END,
        ChangedBy, Activity
    FROM AuditSchema.AuditLog
    WHERE TableName = 'UserLogin'
      AND ActionType = 'REJECTED'
      AND CAST(ChangeDate AS DATE) = CAST(SYSDATETIME() AS DATE)
    ORDER BY EventTime DESC;
END TRY
BEGIN CATCH
    SELECT 'CHECK: native audit file not readable yet -- app-side query still works.' AS Note,
           ERROR_MESSAGE() AS ErrorMessage;
END CATCH;
GO

-- ---------- 4.11 How to guarantee fresh LGIS/LGIF/LGO for the demo ----------
-- Opening/closing any of the 5 SQL Auth tabs generates a native audit event.
-- To force a LGIF specifically: use SSMS Connect dialog, SQL Auth, correct
-- login (e.g. SmartBank_Customer2) but WRONG password. Dismiss the error. Now re-run
-- 4.8 or 4.10 and the LGIF row is there.
-- No sp_Login call needed for any of this -- the events come from actual
-- SSMS connect / disconnect actions.


-- ================================================================
-- REQUIREMENT 5: BACKUP HAS BEEN RUNNING FOR AT LEAST 3 DAYS
-- ================================================================

-- ---------- 5.1 The 3 scheduled backup jobs ----------
-- TAB A (Admin)
SELECT
    j.name          AS JobName,
    j.enabled       AS IsEnabled,
    s.name          AS ScheduleName,
    CASE s.freq_subday_type
        WHEN 4 THEN CONCAT('Every ', s.freq_subday_interval, ' minute(s)')
        WHEN 8 THEN CONCAT('Every ', s.freq_subday_interval, ' hour(s)')
        ELSE 'Once daily' END AS RunFrequency,
    j.description   AS Description
FROM msdb.dbo.sysjobs j
LEFT JOIN msdb.dbo.sysjobschedules js ON j.job_id      = js.job_id
LEFT JOIN msdb.dbo.sysschedules   s  ON js.schedule_id = s.schedule_id
WHERE j.name LIKE N'SmartBankDB - %Backup%'
ORDER BY j.name;
GO

-- ---------- 5.2 Job run history for the last 3+ days ----------
-- TAB A (Admin)
SELECT
    j.name AS JobName,
    msdb.dbo.agent_datetime(h.run_date, h.run_time) AS RunAt,
    CASE h.run_status
        WHEN 0 THEN 'FAILED'
        WHEN 1 THEN 'SUCCEEDED'
        WHEN 3 THEN 'CANCELLED'
        WHEN 4 THEN 'IN PROGRESS'
    END AS Outcome,
    STUFF(STUFF(RIGHT('000000' + CAST(h.run_duration AS VARCHAR(6)), 6), 3, 0, ':'), 6, 0, ':') AS DurationHHMMSS
FROM msdb.dbo.sysjobhistory h
JOIN msdb.dbo.sysjobs      j ON j.job_id = h.job_id
WHERE j.name LIKE N'SmartBankDB - %Backup%'
  AND h.step_id = 0
  AND msdb.dbo.agent_datetime(h.run_date, h.run_time) >= DATEADD(DAY, -4, SYSDATETIME())
ORDER BY RunAt DESC;
GO

-- ---------- 5.3 Success/failure summary per day ----------
-- TAB A (Admin)
SELECT
    j.name AS JobName,
    CAST(msdb.dbo.agent_datetime(h.run_date, h.run_time) AS DATE) AS RunDay,
    SUM(CASE WHEN h.run_status = 1 THEN 1 ELSE 0 END) AS SuccessfulRuns,
    SUM(CASE WHEN h.run_status = 0 THEN 1 ELSE 0 END) AS FailedRuns
FROM msdb.dbo.sysjobhistory h
JOIN msdb.dbo.sysjobs      j ON j.job_id = h.job_id
WHERE j.name LIKE N'SmartBankDB - %Backup%'
  AND h.step_id = 0
  AND msdb.dbo.agent_datetime(h.run_date, h.run_time) >= DATEADD(DAY, -4, SYSDATETIME())
GROUP BY j.name, CAST(msdb.dbo.agent_datetime(h.run_date, h.run_time) AS DATE)
ORDER BY RunDay DESC, JobName;
GO

-- ---------- 5.4 Recovery model + backup file history in msdb ----------
-- TAB A (Admin)
SELECT recovery_model_desc FROM sys.databases WHERE name = 'SmartBankDB';
GO
SELECT TOP 20
    bs.database_name,
    bs.type                                        AS BackupType,
    bs.backup_start_date,
    bs.backup_finish_date,
    CAST(bs.backup_size / 1048576.0 AS DECIMAL(10,2)) AS SizeMB,
    bmf.physical_device_name                       AS BackupFile
FROM msdb.dbo.backupset bs
JOIN msdb.dbo.backupmediafamily bmf ON bmf.media_set_id = bs.media_set_id
WHERE bs.database_name = 'SmartBankDB'
ORDER BY bs.backup_start_date DESC;
GO

-- ---------- 5.5 Manually trigger a Full backup during the demo ----------
-- TAB A (Admin)
EXEC msdb.dbo.sp_start_job @job_name = N'SmartBankDB - Full Backup';
GO

-- ---------- 5.6 Verify the newest backup is intact AND encrypted ----------
-- TAB A (Admin)
DECLARE @NewestBackup NVARCHAR(260) = (
    SELECT TOP 1 bmf.physical_device_name
    FROM msdb.dbo.backupset bs
    JOIN msdb.dbo.backupmediafamily bmf ON bmf.media_set_id = bs.media_set_id
    WHERE bs.database_name = 'SmartBankDB'
      AND bs.type = 'D'
    ORDER BY bs.backup_finish_date DESC
);
SELECT @NewestBackup AS FileBeingVerified;

DECLARE @Sql NVARCHAR(MAX) =
    N'RESTORE HEADERONLY FROM DISK = ''' + @NewestBackup + N''';';
EXEC sp_executesql @Sql;

SET @Sql = N'RESTORE FILELISTONLY FROM DISK = ''' + @NewestBackup + N''';';
EXEC sp_executesql @Sql;

SET @Sql = N'RESTORE VERIFYONLY FROM DISK = ''' + @NewestBackup + N''';';
EXEC sp_executesql @Sql;
GO


-- ================================================================
-- REQUIREMENT 6: RESTORE AN ENCRYPTED BACKUP ON ANOTHER SQL INSTANCE
-- ================================================================
-- The RESTORE runs on the SECOND instance, not this one. See prior
-- walkthrough for full setup steps. Below is the SQL for the second
-- instance's admin (Windows Auth) window.
-- ================================================================

/*  ==== RUN ON THE SECOND SQL INSTANCE ONLY -- NOT THIS ONE ====

-- ---------- 6.1 Certificate setup on the second instance ----------
USE master;
GO

IF NOT EXISTS (SELECT 1 FROM sys.symmetric_keys WHERE name = '##MS_DatabaseMasterKey##')
    CREATE MASTER KEY ENCRYPTION BY PASSWORD = 'SecondInstance_MasterDMK_P@ss2026!';
GO

CREATE CERTIFICATE BackupEncryptCert
    FROM FILE = 'C:\SQLKeys\BackupEncryptCert.cer'
    WITH PRIVATE KEY (
        FILE = 'C:\SQLKeys\BackupEncryptCert.pvk',
        DECRYPTION BY PASSWORD = 'SmartBank_KeyBackup_P@ss2026!'
    );
GO

CREATE CERTIFICATE TDE_SmartBankDB_Cert
    FROM FILE = 'C:\SQLKeys\TDE_SmartBankDB_Cert.cer'
    WITH PRIVATE KEY (
        FILE = 'C:\SQLKeys\TDE_SmartBankDB_Cert.pvk',
        DECRYPTION BY PASSWORD = 'SmartBank_KeyBackup_P@ss2026!'
    );
GO

-- ---------- 6.2 Restore the latest Full backup ----------
RESTORE DATABASE SmartBankDB
FROM DISK = 'C:\SQLBackups\Full\SmartBankDB_Full_<timestamp>.bak'
WITH
    MOVE 'SmartBankDB'     TO 'C:\Program Files\Microsoft SQL Server\MSSQL16.MSSQLSERVER\MSSQL\DATA\SmartBankDB.mdf',
    MOVE 'SmartBankDB_log' TO 'C:\Program Files\Microsoft SQL Server\MSSQL16.MSSQLSERVER\MSSQL\DATA\SmartBankDB_log.ldf',
    REPLACE, STATS = 10;
GO

-- ---------- 6.3 Import the CLE certificate + verify data is readable ----------
USE SmartBankDB;
GO

IF NOT EXISTS (SELECT 1 FROM sys.symmetric_keys WHERE name = '##MS_DatabaseMasterKey##')
    CREATE MASTER KEY ENCRYPTION BY PASSWORD = 'SecondInstance_DBMasterKey_P@ss2026!';
GO

CREATE CERTIFICATE CLE_ICNumber_Cert
    FROM FILE = 'C:\SQLKeys\CLE_ICNumber_Cert.cer'
    WITH PRIVATE KEY (
        FILE = 'C:\SQLKeys\CLE_ICNumber_Cert.pvk',
        DECRYPTION BY PASSWORD = 'SmartBank_KeyBackup_P@ss2026!'
    );
GO

SELECT
    (SELECT COUNT(*) FROM dbo.Staff)             AS StaffCount,
    (SELECT COUNT(*) FROM dbo.Customer)          AS CustomerCount,
    (SELECT COUNT(*) FROM dbo.Account)           AS AccountCount,
    (SELECT COUNT(*) FROM dbo.TransactionRecord) AS TransactionCount;
GO

OPEN SYMMETRIC KEY CLE_ICNumber_SymKey DECRYPTION BY CERTIFICATE CLE_ICNumber_Cert;
SELECT TOP 5
    CustomerID, CustomerName,
    CONVERT(NVARCHAR(20), DecryptByKey(ICNumber)) AS ICNumber_Decrypted
FROM dbo.Customer;
CLOSE SYMMETRIC KEY CLE_ICNumber_SymKey;
GO

==== END OF SECOND-INSTANCE SECTION ==== */


-- ================================================================
-- REQUIREMENT 7: POINT-IN-TIME RESTORE AFTER EXAMINER-INITIATED DELETE
-- ================================================================
-- All deletes + all recovery calls run in TAB A (Admin), since raw
-- DELETE on dbo.<table> and sp_RecoverX both require elevated context.
-- FK-safe pattern: create disposable rows first, delete + recover those.
-- ================================================================

-- ---------- 7.1 Setup: create disposable rows to delete + recover ----------
-- TAB A (Admin)
INSERT INTO dbo.Staff (StaffName, Position, Branch, Phone, Salary, IsActive)
VALUES (N'Practice DeleteMe Staff', N'Bank Officer', N'Demo Branch', N'0100000001', 4000.00, 1);

OPEN SYMMETRIC KEY CLE_ICNumber_SymKey DECRYPTION BY CERTIFICATE CLE_ICNumber_Cert;
DECLARE @DemoICNumber NVARCHAR(20) = N'700101010001';
INSERT INTO dbo.Customer (CustomerName, ICNumber, ICNumberHash, Phone, Address, IsActive)
VALUES (
    N'Practice DeleteMe Customer',
    EncryptByKey(Key_GUID('CLE_ICNumber_SymKey'), CONVERT(VARBINARY(MAX), @DemoICNumber)),
    HASHBYTES('SHA2_256', @DemoICNumber),
    N'0100000002', N'Demo Address for Recovery Practice', 1
);
CLOSE SYMMETRIC KEY CLE_ICNumber_SymKey;

DECLARE @DemoCustomerID INT = (SELECT TOP 1 CustomerID FROM dbo.Customer WHERE CustomerName = N'Practice DeleteMe Customer');

INSERT INTO dbo.Account (CustomerID, AccountType, Balance, IsActive)
VALUES (@DemoCustomerID, N'Savings', 500.00, 1);
DECLARE @DemoAccountID INT = SCOPE_IDENTITY();

INSERT INTO dbo.TransactionRecord (AccountID, Amount, TransactionType)
VALUES (@DemoAccountID, 500.00, N'Deposit');

WAITFOR DELAY '00:00:01';

SELECT * FROM dbo.Staff             WHERE StaffName    = N'Practice DeleteMe Staff';
SELECT * FROM dbo.Customer          WHERE CustomerID   = @DemoCustomerID;
SELECT * FROM dbo.Account           WHERE AccountID    = @DemoAccountID;
SELECT * FROM dbo.TransactionRecord WHERE AccountID    = @DemoAccountID;
GO

-- ---------- FK cleanup pattern -- only if examiner insists on deleting a live row ----------
-- Deleting a Staff row with a login attached:
--   DELETE FROM dbo.UserLogin WHERE StaffID = <StaffID>;
--   DELETE FROM dbo.Staff     WHERE StaffID = <StaffID>;
--
-- Deleting a Customer row with login + accounts:
--   DELETE FROM dbo.TransactionRecord WHERE AccountID IN (SELECT AccountID FROM dbo.Account WHERE CustomerID = <ID>);
--   DELETE FROM dbo.PendingApproval   WHERE AccountID IN (SELECT AccountID FROM dbo.Account WHERE CustomerID = <ID>);
--   DELETE FROM dbo.Account           WHERE CustomerID = <ID>;
--   DELETE FROM dbo.UserLogin         WHERE CustomerID = <ID>;
--   DELETE FROM dbo.Customer          WHERE CustomerID = <ID>;

-- ---------- 7.2 Delete + recover the disposable Staff row ----------
-- TAB A (Admin)
DECLARE @TargetStaffID INT = (SELECT TOP 1 StaffID FROM dbo.Staff WHERE StaffName = N'Practice DeleteMe Staff');
DELETE FROM dbo.Staff WHERE StaffID = @TargetStaffID;

-- Recovery goes through the RecoveryAdmin role -- switch to TAB opened as SmartBank_DBA1:
DECLARE @AsOfDateTime DATETIME2 = (
    SELECT TOP 1 SysStartTime FROM dbo.vw_Staff_History
    WHERE StaffID = @TargetStaffID AND SysEndTime < '9999-12-31 23:59:59.9999999'
    ORDER BY SysEndTime DESC
);
SELECT @AsOfDateTime AS RestoringToThisTimestamp;

DECLARE @Success BIT, @Message NVARCHAR(200);
EXEC dbo.sp_RecoverStaff
    @StaffID      = @TargetStaffID,
    @AsOfDateTime = @AsOfDateTime,
    @Success      = @Success OUTPUT,
    @Message      = @Message OUTPUT;
SELECT @Success AS Success, @Message AS Message;

SELECT * FROM dbo.Staff WHERE StaffID = @TargetStaffID;
GO

-- ---------- 7.3 Delete + recover the disposable Customer row ----------
-- TAB A (Admin)
DECLARE @TargetCustomerID INT = (SELECT TOP 1 CustomerID FROM dbo.Customer WHERE CustomerName = N'Practice DeleteMe Customer');
DECLARE @TargetAccountForCustomer INT = (SELECT AccountID FROM dbo.Account WHERE CustomerID = @TargetCustomerID);

DELETE FROM dbo.PendingApproval   WHERE AccountID  = @TargetAccountForCustomer;
DELETE FROM dbo.TransactionRecord WHERE AccountID  = @TargetAccountForCustomer;
DELETE FROM dbo.Account           WHERE CustomerID = @TargetCustomerID;
DELETE FROM dbo.Customer          WHERE CustomerID = @TargetCustomerID;

DECLARE @AsOfDateTime DATETIME2 = (
    SELECT TOP 1 SysStartTime FROM dbo.vw_Customer_History
    WHERE CustomerID = @TargetCustomerID AND SysEndTime < '9999-12-31 23:59:59.9999999'
    ORDER BY SysEndTime DESC
);

DECLARE @Success BIT, @Message NVARCHAR(200);
EXEC dbo.sp_RecoverCustomer
    @CustomerID   = @TargetCustomerID,
    @AsOfDateTime = @AsOfDateTime,
    @Success      = @Success OUTPUT,
    @Message      = @Message OUTPUT;
SELECT @Success AS Success, @Message AS Message;

SELECT CustomerID, CustomerName, Phone, Address FROM dbo.Customer WHERE CustomerID = @TargetCustomerID;
GO

-- ---------- 7.4 Delete + recover a fresh disposable Account row ----------
-- TAB A (Admin)
DECLARE @TargetCustomerID INT = (SELECT TOP 1 CustomerID FROM dbo.Customer WHERE CustomerName = N'Practice DeleteMe Customer');
INSERT INTO dbo.Account (CustomerID, AccountType, Balance, IsActive)
VALUES (@TargetCustomerID, N'Savings', 750.00, 1);
DECLARE @TargetAccountID INT = SCOPE_IDENTITY();
WAITFOR DELAY '00:00:01';

DELETE FROM dbo.Account WHERE AccountID = @TargetAccountID;

DECLARE @AsOfDateTime DATETIME2 = (
    SELECT TOP 1 SysStartTime FROM dbo.vw_Account_History
    WHERE AccountID = @TargetAccountID AND SysEndTime < '9999-12-31 23:59:59.9999999'
    ORDER BY SysEndTime DESC
);

DECLARE @Success BIT, @Message NVARCHAR(200);
EXEC dbo.sp_RecoverAccount
    @AccountID    = @TargetAccountID,
    @AsOfDateTime = @AsOfDateTime,
    @Success      = @Success OUTPUT,
    @Message      = @Message OUTPUT;
SELECT @Success AS Success, @Message AS Message;

SELECT * FROM dbo.Account WHERE AccountID = @TargetAccountID;
GO

-- ---------- 7.5 Delete + recover a Transaction row (always FK-safe) ----------
-- TAB A (Admin)
DECLARE @TargetTransID INT = (SELECT TOP 1 TransID FROM dbo.TransactionRecord ORDER BY TransID DESC);
SELECT @TargetTransID AS TransactionBeingUsed;
SELECT * FROM dbo.TransactionRecord WHERE TransID = @TargetTransID;
WAITFOR DELAY '00:00:01';

DELETE FROM dbo.TransactionRecord WHERE TransID = @TargetTransID;

DECLARE @AsOfDateTime DATETIME2 = (
    SELECT TOP 1 SysStartTime FROM dbo.vw_TransactionRecord_History
    WHERE TransID = @TargetTransID AND SysEndTime < '9999-12-31 23:59:59.9999999'
    ORDER BY SysEndTime DESC
);

DECLARE @Success BIT, @Message NVARCHAR(200);
EXEC dbo.sp_RecoverTransactionRecord
    @TransID      = @TargetTransID,
    @AsOfDateTime = @AsOfDateTime,
    @Success      = @Success OUTPUT,
    @Message      = @Message OUTPUT;
SELECT @Success AS Success, @Message AS Message;

SELECT * FROM dbo.TransactionRecord WHERE TransID = @TargetTransID;
GO

-- ---------- 7.6 Fallback: browse history view directly ----------
-- TAB A (Admin) -- proves the data isn't lost even without recovery
DECLARE @TargetStaffID INT = (SELECT TOP 1 StaffID FROM dbo.Staff WHERE StaffName = N'Practice DeleteMe Staff');
DECLARE @TargetCustomerID INT = (SELECT TOP 1 CustomerID FROM dbo.Customer WHERE CustomerName = N'Practice DeleteMe Customer');

SELECT * FROM dbo.vw_Staff_History    WHERE StaffID    = @TargetStaffID    ORDER BY SysStartTime DESC;
SELECT * FROM dbo.vw_Customer_History WHERE CustomerID = @TargetCustomerID ORDER BY SysStartTime DESC;
GO


-- ================================================================
-- REQUIREMENT 8: ADD USERS / CHANGE PERMISSIONS AND SHOW AUDIT
-- ================================================================

-- ---------- 8.1 Add a new user via sp_ManageStaff (as Manager) ----------
-- TAB B (Manager)
DECLARE @Success BIT, @Message NVARCHAR(200);
EXEC dbo.sp_ManageStaff
    @StaffName = N'Demo NewUser',
    @Position  = N'Bank Officer',
    @Branch    = N'KL Branch',
    @Phone     = N'0166666666',
    @Salary    = 4800.00,
    @Success   = @Success OUTPUT,
    @Message   = @Message OUTPUT;
SELECT @Success AS Success, @Message AS Message;
GO

-- ---------- 8.2 Show the AuditLog rows generated by 8.1 ----------
-- TAB A (Admin) -- expect: INSERT rows for Staff + UserLogin, attributed to SmartBank_Manager1
SELECT TOP 20 LogID, TableName, ColumnName, RecordID, ActionType, ChangedBy, Activity, ChangeDate
FROM AuditSchema.AuditLog
WHERE ChangeDate >= DATEADD(MINUTE, -5, SYSDATETIME())
ORDER BY ChangeDate DESC;
GO

-- ---------- 8.3 Make a permission change (GRANT then REVOKE) ----------
-- TAB A (Admin)  -- run as dbo/sysadmin
IF DATABASE_PRINCIPAL_ID('DemoAuditRole') IS NULL
    CREATE ROLE DemoAuditRole;
GO
GRANT SELECT ON dbo.vw_StaffOwnRecord TO DemoAuditRole;
GO
REVOKE SELECT ON dbo.vw_StaffOwnRecord FROM DemoAuditRole;
GO
DROP ROLE DemoAuditRole;
GO

-- ---------- 8.4 Show the permission changes in the native audit file ----------
-- TAB opened as SmartBank_DBA1
BEGIN TRY
    SELECT TOP 20
        event_time, action_id, server_principal_name,
        database_principal_name, object_name, statement
    FROM sys.fn_get_audit_file('C:\SQLAudit\*.sqlaudit', DEFAULT, DEFAULT)
    WHERE event_time >= DATEADD(MINUTE, -5, SYSDATETIME())
      AND action_id IN ('GR', 'RVK', 'DR')
    ORDER BY event_time DESC;
END TRY
BEGIN CATCH
    SELECT 'CHECK: audit file might not have events yet -- wait a few seconds and re-run.' AS Note,
           ERROR_MESSAGE() AS ErrorMessage;
END CATCH;
GO

-- ---------- 8.5 Password change captured in audit ----------
-- TAB E (Customer 2)  -- sp_ChangePassword itself uses sp_Login-style
--                        credential verification; this stays as an explicit
--                        password-management API call.
DECLARE @Success BIT, @Message NVARCHAR(200);
EXEC dbo.sp_ChangePassword
    @Username    = N'SmartBank_Customer2',
    @OldPassword = N'Customer2P@ss!',
    @NewPassword = N'NewCustomer2P@ss!',
    @Success     = @Success OUTPUT,
    @Message     = @Message OUTPUT;
SELECT @Success AS Success, @Message AS Message;
GO

-- Show the audit rows generated -- TAB A (Admin)
-- EXPECT: UPDATE rows on UserLogin for PasswordHash + PasswordLastChanged.
-- The Activity column redacts hash bytes; audit never stores the new password.
SELECT TOP 10 LogID, TableName, ColumnName, RecordID, ActionType, ChangedBy, Activity, ChangeDate
FROM AuditSchema.AuditLog
WHERE TableName = 'UserLogin'
  AND ChangeDate >= DATEADD(MINUTE, -1, SYSDATETIME())
ORDER BY ChangeDate DESC;
GO

-- Reset password back -- TAB E (Customer 2)
-- Note: the logon trigger doesn't re-authenticate mid-session, so cust2's
-- SESSION_CONTEXT still points at cust2 even after their password changed.
DECLARE @Success BIT, @Message NVARCHAR(200);
EXEC dbo.sp_ChangePassword
    @Username    = N'SmartBank_Customer2',
    @OldPassword = N'NewCustomer2P@ss!',
    @NewPassword = N'Customer2P@ss!',
    @Success     = @Success OUTPUT,
    @Message     = @Message OUTPUT;
SELECT @Success AS Success, @Message AS Message;
GO


-- ================================================================
-- REQUIREMENT 9: ENCRYPTED DATA DECRYPTS AUTOMATICALLY FOR RIGHT USER
-- ================================================================

-- ---------- 9.1 DDM: Manager sees real balances via vw_AccountAll ----------
-- TAB B (Manager)  -- EXPECT: real Balance values (Manager has UNMASK)
SELECT AccountID, CustomerID, AccountType, Balance FROM dbo.vw_AccountAll ORDER BY AccountID;
GO

-- ---------- 9.2 DDM: Officer sees the same view but Balance is masked to 0.00 ----------
-- TAB C (Officer)  -- EXPECT: same rows as Manager but every Balance shows 0.00
SELECT AccountID, CustomerID, AccountType, Balance FROM dbo.vw_AccountAll ORDER BY AccountID;
GO

-- ---------- 9.3 DDM: Customer sees the true Balance for THEIR OWN account only ----------
-- TAB D (Customer 1)  -- EXPECT: cust1's row(s) with real Balance
SELECT AccountID, CustomerID, Balance FROM dbo.vw_AccountOwn ORDER BY AccountID;
GO

-- ---------- 9.4 CLE: Customer decrypts their OWN IC Number ----------
-- TAB D (Customer 1)  -- proc reads CustomerID from SESSION_CONTEXT (set by trigger)
EXEC dbo.sp_DecryptOwnICNumber;
GO

-- ---------- 9.5 CLE: Officer decrypts any customer's IC Number ----------
-- Step 1: TAB A (Admin) -- pick a customer ID
SELECT TOP 1 CustomerID FROM dbo.Customer ORDER BY CustomerID;
GO

-- Step 2: TAB C (Officer) -- REPLACE 1 with the CustomerID from Step 1
EXEC dbo.sp_DecryptICNumber @CustomerID = 1;
GO

-- ---------- 9.6 CLE: IC Number at rest looks like ciphertext ----------
-- TAB A (Admin) -- shows the raw encrypted bytes stored on disk
SELECT TOP 5
    CustomerID, CustomerName,
    sys.fn_varbintohexstr(ICNumber) AS StoredCiphertext,
    DATALENGTH(ICNumber) AS EncryptedBytes
FROM dbo.Customer;
GO

-- ---------- 9.7 TDE: whole database is encrypted at rest ----------
-- TAB A (Admin)
SELECT
    DB_NAME(database_id) AS DatabaseName,
    encryption_state,
    CASE encryption_state
        WHEN 3 THEN 'ENCRYPTED'
        WHEN 2 THEN 'ENCRYPTION IN PROGRESS'
        WHEN 1 THEN 'UNENCRYPTED'
        ELSE 'OTHER' END AS StateDescription
FROM sys.dm_database_encryption_keys
WHERE database_id = DB_ID('SmartBankDB');
GO

-- ---------- 9.8 CLE: DBA CANNOT decrypt IC numbers ----------
-- TAB opened as SmartBank_DBA1
DECLARE @AnyCustomerID INT = 1;   -- any valid CustomerID

BEGIN TRY
    EXEC dbo.sp_DecryptICNumber @CustomerID = @AnyCustomerID;
    SELECT 'FAIL: DBA was able to decrypt an IC number!' AS Result;
END TRY
BEGIN CATCH
    SELECT 'PASS: DBA is denied on sp_DecryptICNumber.' AS Result,
           ERROR_NUMBER() AS ErrNum, ERROR_MESSAGE() AS ErrMsg;
END CATCH;

BEGIN TRY
    OPEN SYMMETRIC KEY CLE_ICNumber_SymKey DECRYPTION BY CERTIFICATE CLE_ICNumber_Cert;
    SELECT 'FAIL: DBA opened the CLE key!' AS Result;
    CLOSE SYMMETRIC KEY CLE_ICNumber_SymKey;
END TRY
BEGIN CATCH
    SELECT 'PASS: DBA is denied on direct CLE key access.' AS Result,
           ERROR_NUMBER() AS ErrNum, ERROR_MESSAGE() AS ErrMsg;
END CATCH;
GO

-- ---------- 9.9 Passwords are HASHED at rest (Confidentiality C3 proof) ----------
-- TAB A (Admin)
SELECT
    Username,
    DATALENGTH(PasswordHash)                    AS HashBytes,   -- expect 64
    DATALENGTH(Salt)                            AS SaltBytes,   -- expect 32
    sys.fn_varbintohexstr(PasswordHash)         AS HashPreview
FROM dbo.UserLogin
WHERE Username IN ('SmartBank_Manager1','SmartBank_DBA1','SmartBank_Officer1','SmartBank_Customer1','SmartBank_Customer2')
ORDER BY Username;
GO

-- Different users -> different salts -> different hashes
SELECT
    a.Username                             AS UserA,
    b.Username                             AS UserB,
    CASE WHEN a.Salt         <> b.Salt         THEN 'DIFFERENT' ELSE 'SAME' END AS SaltComparison,
    CASE WHEN a.PasswordHash <> b.PasswordHash THEN 'DIFFERENT' ELSE 'SAME' END AS HashComparison
FROM dbo.UserLogin a
JOIN dbo.UserLogin b ON a.Username = 'SmartBank_Customer1' AND b.Username = 'SmartBank_Customer2';
GO

-- Verification without seeing the hash
SELECT
    'SmartBank_Customer1' AS Username,
    dbo.fn_VerifyPassword('SmartBank_Customer1', 'Customer1P@ss!')    AS CorrectPasswordCheck,   -- expect 1
    dbo.fn_VerifyPassword('SmartBank_Customer1', 'DefinitelyWrong!')  AS WrongPasswordCheck;     -- expect 0
GO


-- ================================================================
-- APPENDIX A: LIKELY EXAMINER QUESTIONS
-- ================================================================
-- Q  "Login as a Bank Officer"                           -> TAB C (already logged in)
-- Q  "Now as a Customer"                                 -> TAB D
-- Q  "Show me the list of users for each role"           -> Section 2.1
-- Q  "What permissions does each role have?"             -> Section 2.3
-- Q  "As a Customer, show me staff name + contact"       -> Section 3.1
-- Q  "As an Officer, section 1 requirement 4"            -> Section 3.2
-- Q  "As a Customer, show your own accounts / txns"      -> Section 3.3
-- Q  "Do they have direct access to the table?"          -> Section 3.5
-- Q  "Can Officer update their own record?"              -> Section 3.6
-- Q  "Can Officer update someone else's record?"         -> Section 3.8
-- Q  "As Manager, update record 3 (an Officer)"          -> Section 3.18
-- Q  "Try to update record 7 / a non-Officer record"     -> Section 3.19
-- Q  "As Officer, delete a customer record"              -> Section 3.20
-- Q  "As Officer, create a new customer"                 -> Section 3.21
-- Q  "As Officer, open an account"                       -> Section 3.22
-- Q  "As a Customer, deposit money"                      -> Section 3.9
-- Q  "As a Customer, withdraw"                           -> Section 3.10
-- Q  "Try to withdraw from someone else's account"       -> Section 3.11
-- Q  "Try to overdraft"                                  -> Section 3.12
-- Q  "As Officer, try to move money"                     -> Section 3.14
-- Q  "Deposit RM15,000 -- what happens?"                 -> Section 3.15
-- Q  "As Manager, approve the pending request"           -> Section 3.16
-- Q  "As Manager, REJECT a pending request"              -> Section 3.23
-- Q  "Transfer money between customers"                  -> Section 3.17
-- Q  "As DBA, try to read customer data"                 -> Section 3.24
-- Q  "Prove RLS isolates Officer1 from Officer2"         -> Section 3.25
-- Q  "Two Managers have same role permissions?"          -> Section 3.26
-- Q  "Show a failed login in the native audit"           -> Section 1.6 -> 4.8
-- Q  "As DBA, try to decrypt an IC number"               -> Section 9.8
-- Q  "Add a new record in the staff table"               -> Section 8.1
-- Q  "Show whatever changes happened on staff today"     -> Section 4.2
-- Q  "Is there any denying?"                             -> Section 4.3
-- Q  "Show me every login event today"                   -> Section 4.8 (native audit)
-- Q  "Prove all 5 test users logged in and out"          -> Section 4.9
-- Q  "Show me a failed login in the audit"               -> Section 4.7 (from 1.5) + 4.8 (native LGIF)
-- Q  "Show me your backup schedule"                      -> Section 5.1
-- Q  "Prove backups have run consecutively"              -> Section 5.2, 5.3
-- Q  "Prove the backup file isn't corrupted"             -> Section 5.6
-- Q  "Prove the backup file is encrypted"                -> Section 5.6 (HEADERONLY)
-- Q  "Manually trigger a full backup"                    -> Section 5.5
-- Q  "Restore this backup on another instance"           -> Section 6
-- Q  "Delete a Customer record and get it back"          -> Section 7.3
-- Q  "Add a user and prove it's audited"                 -> Section 8.1, 8.2
-- Q  "Change a permission and prove it's audited"        -> Section 8.3, 8.4
-- Q  "Change a user's password and prove it's audited"   -> Section 8.5
-- Q  "Customer sees their own IC number decrypted"       -> Section 9.4
-- Q  "Prove IC number is encrypted at rest"              -> Section 9.6
-- Q  "Prove passwords are hashed, not plaintext"         -> Section 9.9


-- ================================================================
-- APPENDIX B: TROUBLESHOOTING DURING THE DEMO
-- ================================================================
-- Problem: "Empty result set from vw_AccountOwn even though I connected"
--   Cause A: The logon trigger didn't fire. Verify by running:
--       SELECT CAST(SESSION_CONTEXT(N'UserType') AS NVARCHAR(20)) AS UserType,
--              CAST(SESSION_CONTEXT(N'StaffID')  AS INT)          AS StaffID,
--              CAST(SESSION_CONTEXT(N'CustomerID') AS INT)        AS CustomerID;
--     If all NULL, the trigger might be disabled. From a sysadmin tab:
--       ENABLE TRIGGER trg_AutoSetSessionContext ON ALL SERVER;
--   Cause B: Wrong tab. Confirm SUSER_SNAME() matches the expected login
--     for this block.
--
-- Problem: "Login attempt returns 'account locked out'"
--   Fix from Admin tab:
--     UPDATE dbo.UserLogin SET FailedLoginAttempts = 0, LockoutUntil = NULL
--     WHERE Username = '<the_username>';
--
-- Problem: "sp_ManageStaff says 'Position must be Bank Officer'"
--   Cause: sp_ManageStaff by design only manages Bank Officer records.
--   Fix: pass @Position = 'Bank Officer'.
--
-- Problem: "sp_RecoverX says 'No historical record found'"
--   Fix: query dbo.vw_<Table>_History for the row's actual SysStartTime
--     values first, pick one, retry.
--
-- Problem: "Native audit file query returns nothing"
--   Fix: wait a few seconds (audit flushes on interval), re-run, or
--     verify sys.dm_server_audit_status shows status_desc = 'STARTED'.
--
-- Problem: "The logon trigger is misbehaving / blocking demo"
--   Emergency disable (from ANY sysadmin connection):
--     DISABLE TRIGGER trg_AutoSetSessionContext ON ALL SERVER;
--   Everything reverts to needing manual sp_Login calls; no other change.
-- ================================================================