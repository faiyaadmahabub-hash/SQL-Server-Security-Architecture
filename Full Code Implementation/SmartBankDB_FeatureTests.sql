-- SmartBankDB Feature Test
-- Run each block below one at a time (separated by GO).
-- No logging/summary tables here -- just watch the result or error each block produces.

USE SmartBankDB; -- switch to the SmartBankDB database
GO


-- ============================================================
-- STEP 1 of 9 -- SETUP
-- Run once, in order, top to bottom -- plain inserts, no procedures, no bootstrap dance
-- ============================================================

-- Manager, DBA, Officer -- straight into Staff + UserLogin, password already set (no forced expiry)
-- (usernames/passwords below are plain literals we chose ourselves, so every later
-- block can just use them directly -- no lookup table needed)

DECLARE @Salt     VARBINARY(32); -- random per-login salt -- reset below for each identity
DECLARE @Password NVARCHAR(30);  -- plaintext test password -- reset below for each identity

-- Manager
SET @Salt     = CRYPT_GEN_RANDOM(32);
SET @Password = 'ManagerP@ss1!';

-- create the Staff row for the Manager identity
INSERT INTO dbo.Staff (StaffName, Position, Branch, Phone, Salary, IsActive)
VALUES ('Aiman Zulkifli', 'Bank Manager', 'KL Branch', '0111111111', 9000.00, 1);

-- create its UserLogin row -- PasswordHash is SHA2_512(salt + password), same scheme sp_Login checks
INSERT INTO dbo.UserLogin (Username, PasswordHash, Salt, StaffID, UserType, PasswordLastChanged, IsActive)
VALUES (
    'mgr_test',
    HASHBYTES('SHA2_512', @Salt + CONVERT(VARBINARY(4000), @Password)),
    @Salt,
    SCOPE_IDENTITY(), -- StaffID from the INSERT above (safe here: triggers run in their own scope)
    'Staff',
    SYSDATETIME(),    -- PasswordLastChanged = now, so the password is NOT expired
    1
);


-- DBA
SET @Salt     = CRYPT_GEN_RANDOM(32);
SET @Password = 'DbaTestP@ss1!';

-- create the Staff row for the DBA identity
INSERT INTO dbo.Staff (StaffName, Position, Branch, Phone, Salary, IsActive)
VALUES ('Nabil Hakim', 'DBA', 'HQ', '0122222222', 8000.00, 1);

INSERT INTO dbo.UserLogin (Username, PasswordHash, Salt, StaffID, UserType, PasswordLastChanged, IsActive)
VALUES (
    'dba_test',
    HASHBYTES('SHA2_512', @Salt + CONVERT(VARBINARY(4000), @Password)),
    @Salt,
    SCOPE_IDENTITY(),
    'Staff',
    SYSDATETIME(),
    1
);


-- Officer
SET @Salt     = CRYPT_GEN_RANDOM(32);
SET @Password = 'OfficerP@ss1!';

-- create the Staff row for the Officer identity
INSERT INTO dbo.Staff (StaffName, Position, Branch, Phone, Salary, IsActive)
VALUES ('Farah Aina', 'Bank Officer', 'KL Branch', '0133333333', 4500.00, 1);

INSERT INTO dbo.UserLogin (Username, PasswordHash, Salt, StaffID, UserType, PasswordLastChanged, IsActive)
VALUES (
    'ofc_test',
    HASHBYTES('SHA2_512', @Salt + CONVERT(VARBINARY(4000), @Password)),
    @Salt,
    SCOPE_IDENTITY(),
    'Staff',
    SYSDATETIME(),
    1
);

GO

-- Customer1 + Customer2 -- straight into Customer + Account + UserLogin
-- (ICNumber encrypted with the real CLE key, matching sp_ManageCustomer's own encryption)

-- unlock the CLE symmetric key so EncryptByKey can use it below
OPEN SYMMETRIC KEY CLE_ICNumber_SymKey DECRYPTION BY CERTIFICATE CLE_ICNumber_Cert;

DECLARE @ICNumber NVARCHAR(20); -- plaintext IC number -- reset below for each customer

-- Customer1
SET @ICNumber = '990101011234';

-- create Customer1 -- ICNumber is CLE-encrypted, ICNumberHash is the lookup hash (used by sp_ManageCustomer's own duplicate check)
INSERT INTO dbo.Customer (CustomerName, ICNumber, ICNumberHash, Phone, Address, IsActive)
VALUES (
    'Wei Ming Tan',
    EncryptByKey(Key_GUID('CLE_ICNumber_SymKey'), CONVERT(VARBINARY(MAX), @ICNumber)),
    HASHBYTES('SHA2_256', @ICNumber),
    '0141111111',
    '1 Test Street, KL',
    1
);
DECLARE @CustomerID1 INT = SCOPE_IDENTITY(); -- Customer1's new CustomerID

-- Customer2
SET @ICNumber = '990202021234';

-- create Customer2, same pattern as Customer1
INSERT INTO dbo.Customer (CustomerName, ICNumber, ICNumberHash, Phone, Address, IsActive)
VALUES (
    'Siti Nurhaliza',
    EncryptByKey(Key_GUID('CLE_ICNumber_SymKey'), CONVERT(VARBINARY(MAX), @ICNumber)),
    HASHBYTES('SHA2_256', @ICNumber),
    '0142222222',
    '2 Test Street, KL',
    1
);
DECLARE @CustomerID2 INT = SCOPE_IDENTITY(); -- Customer2's new CustomerID

CLOSE SYMMETRIC KEY CLE_ICNumber_SymKey; -- re-lock the key now encryption is done

-- Accounts open at RM0.00, same as sp_ManageAccount would leave them
-- funded later via sp_ProcessTransaction in TRANSACTION INTEGRITY
-- (AccountID isn't captured here -- later blocks look it up from dbo.Account by CustomerID)

INSERT INTO dbo.Account (CustomerID, AccountType, Balance, IsActive)
VALUES (@CustomerID1, 'Savings', 0.00, 1);

INSERT INTO dbo.Account (CustomerID, AccountType, Balance, IsActive)
VALUES (@CustomerID2, 'Savings', 0.00, 1);

DECLARE @Salt     VARBINARY(32); -- reset below for each customer
DECLARE @Password NVARCHAR(30);  -- reset below for each customer

-- Customer1's login
SET @Salt     = CRYPT_GEN_RANDOM(32);
SET @Password = 'Customer1P@ss!';

INSERT INTO dbo.UserLogin (Username, PasswordHash, Salt, CustomerID, UserType, PasswordLastChanged, IsActive)
VALUES (
    'cust1_test',
    HASHBYTES('SHA2_512', @Salt + CONVERT(VARBINARY(4000), @Password)),
    @Salt,
    @CustomerID1,
    'Customer',
    SYSDATETIME(),
    1
);


-- Customer2's login
SET @Salt     = CRYPT_GEN_RANDOM(32);
SET @Password = 'Customer2P@ss!';

INSERT INTO dbo.UserLogin (Username, PasswordHash, Salt, CustomerID, UserType, PasswordLastChanged, IsActive)
VALUES (
    'cust2_test',
    HASHBYTES('SHA2_512', @Salt + CONVERT(VARBINARY(4000), @Password)),
    @Salt,
    @CustomerID2,
    'Customer',
    SYSDATETIME(),
    1
);

GO

-- TEST: sanity check that all 5 test identities were created correctly
-- EXPECT: 5 rows -- Manager/DBA/Officer with StaffID set and CustomerID NULL;
--         Customer1/Customer2 with CustomerID + AccountID set and StaffID NULL
SELECT ul.Username, ul.UserType, ul.StaffID, ul.CustomerID, a.AccountID
FROM dbo.UserLogin ul
LEFT JOIN dbo.Account a ON a.CustomerID = ul.CustomerID
WHERE ul.Username IN ('mgr_test', 'dba_test', 'ofc_test', 'cust1_test', 'cust2_test');
GO


-- ============================================================
-- STEP 2 of 9 -- AUTHENTICATION
-- Confidentiality: sp_Login / sp_ChangePassword -- lockout, expiry, weak-password rejection
-- ============================================================

-- TEST: login attempt with a username that doesn't exist
-- EXPECT: Success = 0, generic "invalid login" message (same wording as a wrong
--         password, so a username can't be enumerated by trial and error)
DECLARE @LoginSuccess    BIT;           -- 1 = login succeeded, 0 = rejected
DECLARE @PasswordExpired BIT;           -- 1 = correct password but expired
DECLARE @LoginMessage    NVARCHAR(200); -- human-readable result

-- same generic message as a wrong password, so a username can't be enumerated
EXEC dbo.sp_Login
    @Username        = 'no_such_user_xyz',
    @PlainPassword   = 'whatever',
    @Success         = @LoginSuccess    OUTPUT,
    @PasswordExpired = @PasswordExpired OUTPUT,
    @Message         = @LoginMessage    OUTPUT;

SELECT @LoginSuccess AS Success, @LoginMessage AS Message; -- expect Success = 0, generic invalid-login message
GO

-- TEST: 3 wrong passwords in a row, then the correct password
-- EXPECT: all 4 attempts fail; final SELECT shows Success = 0 with a "locked out"
--         message, and LockoutUntil is a future datetime
DECLARE @Username NVARCHAR(50) = 'cust1_test';
DECLARE @Password NVARCHAR(50) = 'Customer1P@ss!';

DECLARE @LoginSuccess    BIT;
DECLARE @PasswordExpired BIT;
DECLARE @LoginMessage    NVARCHAR(200);
DECLARE @WrongPassword   NVARCHAR(50); -- deliberately incorrect password for the next 3 attempts

SET @WrongPassword = 'Wrong1!';
EXEC dbo.sp_Login -- failed attempt 1/3
    @Username        = @Username,
    @PlainPassword   = @WrongPassword,
    @Success         = @LoginSuccess    OUTPUT,
    @PasswordExpired = @PasswordExpired OUTPUT,
    @Message         = @LoginMessage    OUTPUT;

SET @WrongPassword = 'Wrong2!';
EXEC dbo.sp_Login -- failed attempt 2/3
    @Username        = @Username,
    @PlainPassword   = @WrongPassword,
    @Success         = @LoginSuccess    OUTPUT,
    @PasswordExpired = @PasswordExpired OUTPUT,
    @Message         = @LoginMessage    OUTPUT;

SET @WrongPassword = 'Wrong3!';
EXEC dbo.sp_Login -- failed attempt 3/3 -- this one should trip the lockout (MaxFailedAttempts = 3)
    @Username        = @Username,
    @PlainPassword   = @WrongPassword,
    @Success         = @LoginSuccess    OUTPUT,
    @PasswordExpired = @PasswordExpired OUTPUT,
    @Message         = @LoginMessage    OUTPUT;

-- correct password -- account should already be locked out by now
EXEC dbo.sp_Login
    @Username        = @Username,
    @PlainPassword   = @Password,
    @Success         = @LoginSuccess    OUTPUT,
    @PasswordExpired = @PasswordExpired OUTPUT,
    @Message         = @LoginMessage    OUTPUT;

SELECT @LoginSuccess AS Success, @LoginMessage AS Message; -- expect Success = 0, locked-out message
SELECT LockoutUntil FROM dbo.UserLogin WHERE Username = @Username; -- expect a future datetime
GO

-- TEST: change password to a weak new value ('weak')
-- EXPECT: Success = 0, message says the new password fails complexity rules
--         (needs 8+ chars, upper/lower, digit, symbol)
DECLARE @Username NVARCHAR(50) = 'cust1_test';
DECLARE @Password NVARCHAR(50) = 'Customer1P@ss!';

DECLARE @ChangeSuccess BIT;
DECLARE @ChangeMessage NVARCHAR(200);

-- 'weak' fails fn_ValidatePasswordComplexity (needs 8+ chars, upper/lower, digit, symbol)
EXEC dbo.sp_ChangePassword
    @Username    = @Username,
    @OldPassword = @Password,
    @NewPassword = 'weak',
    @Success     = @ChangeSuccess OUTPUT,
    @Message     = @ChangeMessage OUTPUT;

SELECT @ChangeSuccess AS Success, @ChangeMessage AS Message; -- expect Success = 0, complexity-rejected message
GO


-- ============================================================
-- STEP 3 of 9 -- CONFIDENTIALITY / RBAC / RLS
-- Confidentiality: each role can read only what the assignment allows -- enforced via views + RLS
-- ============================================================

-- TEST: Customer2 logs in and reads everything a Customer is allowed to see
-- EXPECT: all 4 SELECTs succeed -- own account, own transactions, own profile,
--         and the shared staff directory
EXECUTE AS LOGIN = 'SmartBank_Customer'; -- impersonate the Customer SQL login (its GRANT/DENY apply from here)

DECLARE @Username NVARCHAR(50) = 'cust2_test';
DECLARE @Password NVARCHAR(50) = 'Customer2P@ss!';

DECLARE @LoginSuccess    BIT;
DECLARE @PasswordExpired BIT;
DECLARE @LoginMessage    NVARCHAR(200);

-- app-level login: sets SESSION_CONTEXT so RLS views know this is Customer2
EXEC dbo.sp_Login
    @Username        = @Username,
    @PlainPassword   = @Password,
    @Success         = @LoginSuccess    OUTPUT,
    @PasswordExpired = @PasswordExpired OUTPUT,
    @Message         = @LoginMessage    OUTPUT;

SELECT * FROM dbo.vw_AccountOwn;         -- expect: only Customer2's own account
SELECT * FROM dbo.vw_TransactionOwn;     -- expect: success
SELECT * FROM dbo.vw_CustomerOwnProfile; -- expect: success -- check if Phone shows real value or masked XXXX
SELECT * FROM dbo.vw_StaffDirectory;     -- expect: success -- name + contact, visible to all authenticated users

EXEC dbo.sp_Logout; -- clear SESSION_CONTEXT
REVERT;             -- drop impersonation
GO

-- TEST: Customer2 tries direct base-table access, another role's view, DDL, and a
--       direct Balance write -- run one line at a time
-- EXPECT: every statement is denied (no direct table access, no DDL rights, and
--         Balance can only change through sp_ProcessTransaction)
EXECUTE AS LOGIN = 'SmartBank_Customer';

DECLARE @Username NVARCHAR(50) = 'cust2_test';
DECLARE @Password NVARCHAR(50) = 'Customer2P@ss!';

DECLARE @LoginSuccess    BIT;
DECLARE @PasswordExpired BIT;
DECLARE @LoginMessage    NVARCHAR(200);

EXEC dbo.sp_Login
    @Username        = @Username,
    @PlainPassword   = @Password,
    @Success         = @LoginSuccess    OUTPUT,
    @PasswordExpired = @PasswordExpired OUTPUT,
    @Message         = @LoginMessage    OUTPUT;

SELECT * FROM dbo.Staff;                        -- expect: DENY -- no direct base-table access for Customer
SELECT * FROM dbo.Account;                      -- expect: DENY -- same blanket DENY
SELECT * FROM dbo.vw_AccountAll;                -- expect: DENY -- Manager/Officer view, not Customer's
CREATE TABLE dbo.Customer_Test_Table (ID INT);  -- expect: DENY -- DDL should be DBA-only
UPDATE dbo.Account SET Balance = 999999 WHERE CustomerID = (SELECT CustomerID FROM dbo.UserLogin WHERE Username = 'cust2_test'); -- expect: DENY -- only sp_ProcessTransaction may change Balance

EXEC dbo.sp_Logout;
REVERT;
GO

-- TEST: Customer1 deposits RM50 into their own account
-- EXPECT: Success = 1; sets up a real transaction row for the RLS check in the
--         next block to prove Customer2 can't see it
DECLARE @Customer1OwnAccountID INT = (SELECT AccountID FROM dbo.Account WHERE CustomerID = (SELECT CustomerID FROM dbo.UserLogin WHERE Username = 'cust1_test')); -- fetched as dbo before impersonating

EXECUTE AS LOGIN = 'SmartBank_Customer';

DECLARE @Username NVARCHAR(50) = 'cust1_test';
DECLARE @Password NVARCHAR(50) = 'Customer1P@ss!';

DECLARE @LoginSuccess    BIT;
DECLARE @PasswordExpired BIT;
DECLARE @LoginMessage    NVARCHAR(200);

EXEC dbo.sp_Login
    @Username        = @Username,
    @PlainPassword   = @Password,
    @Success         = @LoginSuccess    OUTPUT,
    @PasswordExpired = @PasswordExpired OUTPUT,
    @Message         = @LoginMessage    OUTPUT;

DECLARE @TransactionSuccess BIT;
DECLARE @TransactionMessage NVARCHAR(200);

EXEC dbo.sp_ProcessTransaction
    @AccountID       = @Customer1OwnAccountID,
    @TransactionType = 'Deposit',
    @Amount          = 50.00,
    @Success         = @TransactionSuccess OUTPUT,
    @Message         = @TransactionMessage OUTPUT;

SELECT @TransactionSuccess AS Success, @TransactionMessage AS Message; -- expect Success = 1 -- Customer1's balance is now 50.00

EXEC dbo.sp_Logout;
REVERT;
GO

-- TEST: Customer2 queries their own-data views filtered to Customer1's AccountID
-- EXPECT: both SELECTs return 0 rows -- RLS hides Customer1's account and
--         transactions even when Customer2 asks for them by ID
DECLARE @Customer1AccountID INT = (SELECT AccountID FROM dbo.Account WHERE CustomerID = (SELECT CustomerID FROM dbo.UserLogin WHERE Username = 'cust1_test')); -- fetched as dbo before impersonating

EXECUTE AS LOGIN = 'SmartBank_Customer';

DECLARE @Username NVARCHAR(50) = 'cust2_test';
DECLARE @Password NVARCHAR(50) = 'Customer2P@ss!';

DECLARE @LoginSuccess    BIT;
DECLARE @PasswordExpired BIT;
DECLARE @LoginMessage    NVARCHAR(200);

EXEC dbo.sp_Login
    @Username        = @Username,
    @PlainPassword   = @Password,
    @Success         = @LoginSuccess    OUTPUT,
    @PasswordExpired = @PasswordExpired OUTPUT,
    @Message         = @LoginMessage    OUTPUT;

SELECT * FROM dbo.vw_AccountOwn WHERE AccountID = @Customer1AccountID;     -- expect: 0 rows -- RLS filters out Customer1's account
SELECT * FROM dbo.vw_TransactionOwn WHERE AccountID = @Customer1AccountID; -- expect: 0 rows -- RLS filters out Customer1's deposit too, even though it's a real row

EXEC dbo.sp_Logout;
REVERT;
GO

-- TEST: Officer logs in, reads everything an Officer is allowed to see, then creates
--       a customer + account and updates their own Phone
-- EXPECT: all 5 SELECTs succeed; sp_ManageCustomer and sp_ManageAccount both return
--         Success = 1; sp_UpdateOwnStaffRecord returns Success = 1 and the follow-up
--         SELECT shows Phone = 0135555555
EXECUTE AS LOGIN = 'SmartBank_Officer';

DECLARE @Username NVARCHAR(50) = 'ofc_test';
DECLARE @Password NVARCHAR(50) = 'OfficerP@ss1!';

DECLARE @LoginSuccess    BIT;
DECLARE @PasswordExpired BIT;
DECLARE @LoginMessage    NVARCHAR(200);

EXEC dbo.sp_Login
    @Username        = @Username,
    @PlainPassword   = @Password,
    @Success         = @LoginSuccess    OUTPUT,
    @PasswordExpired = @PasswordExpired OUTPUT,
    @Message         = @LoginMessage    OUTPUT;

SELECT * FROM dbo.vw_AccountAll;     -- expect: success -- Officer sees all customer accounts
SELECT * FROM dbo.vw_TransactionAll; -- expect: success -- Officer sees all transactions
SELECT * FROM dbo.vw_CustomerAll;    -- expect: success -- Officer manages customers
SELECT * FROM dbo.vw_StaffDirectory; -- expect: success -- name + contact, visible to all authenticated users
SELECT * FROM dbo.vw_StaffOwnRecord; -- expect: success -- Officer's own record only (Confidentiality: "view only their own record")

-- Officer manages customer + account (own procs, expect Success = 1)
DECLARE @ManageCustomerSuccess BIT;
DECLARE @ManageCustomerMessage NVARCHAR(200);

-- create a new customer -- proves Bank Officer can manage customer records (Integrity requirement)
EXEC dbo.sp_ManageCustomer
    @CustomerName = 'Kumar Raj',
    @ICNumber     = '990303031234',
    @Phone        = '0143333333',
    @Address      = '3 Test Street, KL',
    @Success      = @ManageCustomerSuccess OUTPUT,
    @Message      = @ManageCustomerMessage OUTPUT;

SELECT @ManageCustomerSuccess AS Success, @ManageCustomerMessage AS Message; -- expect Success = 1

DECLARE @CustomerID3 INT = (SELECT CustomerID FROM dbo.vw_CustomerAll WHERE CustomerName = 'Kumar Raj');

DECLARE @ManageAccountSuccess BIT;
DECLARE @ManageAccountMessage NVARCHAR(200);

-- open an account for that new customer -- proves Bank Officer can manage accounts
EXEC dbo.sp_ManageAccount
    @CustomerID  = @CustomerID3,
    @AccountType = 'Savings',
    @Success     = @ManageAccountSuccess OUTPUT,
    @Message     = @ManageAccountMessage OUTPUT;

SELECT @ManageAccountSuccess AS Success, @ManageAccountMessage AS Message; -- expect Success = 1

-- Officer updates their own contact number (Integrity: "each staff can update their own record except salary")
DECLARE @UpdateOwnSuccess BIT;
DECLARE @UpdateOwnMessage NVARCHAR(200);

EXEC dbo.sp_UpdateOwnStaffRecord
    @Phone   = '0135555555',
    @Success = @UpdateOwnSuccess OUTPUT,
    @Message = @UpdateOwnMessage OUTPUT;

SELECT @UpdateOwnSuccess AS Success, @UpdateOwnMessage AS Message; -- expect Success = 1
SELECT Phone FROM dbo.vw_StaffOwnRecord; -- expect 0135555555 -- confirms the proc actually updated Phone, not just returned success

EXEC dbo.sp_Logout;
REVERT;
GO

-- TEST: Officer tries a Staff salary write, DDL, and the Manager-only sp_ManageStaff
--       -- run one line at a time
-- EXPECT: the UPDATE and CREATE TABLE are both denied; sp_ManageStaff returns
--         Success = 0 (wrong role, not a permission error)
EXECUTE AS LOGIN = 'SmartBank_Officer';

DECLARE @Username NVARCHAR(50) = 'ofc_test';
DECLARE @Password NVARCHAR(50) = 'OfficerP@ss1!';

DECLARE @LoginSuccess    BIT;
DECLARE @PasswordExpired BIT;
DECLARE @LoginMessage    NVARCHAR(200);

EXEC dbo.sp_Login
    @Username        = @Username,
    @PlainPassword   = @Password,
    @Success         = @LoginSuccess    OUTPUT,
    @PasswordExpired = @PasswordExpired OUTPUT,
    @Message         = @LoginMessage    OUTPUT;

UPDATE dbo.Staff SET Salary = 999999;                     -- expect: DENY -- Officer can't touch Staff directly
CREATE TABLE dbo.Officer_Test_Table (ID INT);              -- expect: DENY -- DDL should be DBA-only

DECLARE @UnauthorizedSuccess BIT;
DECLARE @UnauthorizedMessage NVARCHAR(200);

EXEC dbo.sp_ManageStaff -- Manager-only proc -- expect Success = 0
    @StaffName = 'Zul Ariffin',
    @Position  = 'Bank Officer',
    @Branch    = 'X',
    @Phone     = '0100000000',
    @Salary    = 1000,
    @Success   = @UnauthorizedSuccess OUTPUT,
    @Message   = @UnauthorizedMessage OUTPUT;

EXEC dbo.sp_Logout;
REVERT;
GO

-- TEST: Manager logs in, reads everything a Manager is allowed to see, then creates
--       a new Bank Officer
-- EXPECT: all 7 SELECTs succeed; sp_ManageStaff returns Success = 1 for the new
--         'Priya Devi' record
EXECUTE AS LOGIN = 'SmartBank_Manager';

DECLARE @Username NVARCHAR(50) = 'mgr_test';
DECLARE @Password NVARCHAR(50) = 'ManagerP@ss1!';

DECLARE @LoginSuccess    BIT;
DECLARE @PasswordExpired BIT;
DECLARE @LoginMessage    NVARCHAR(200);

EXEC dbo.sp_Login
    @Username        = @Username,
    @PlainPassword   = @Password,
    @Success         = @LoginSuccess    OUTPUT,
    @PasswordExpired = @PasswordExpired OUTPUT,
    @Message         = @LoginMessage    OUTPUT;

SELECT * FROM dbo.vw_StaffOwnRecord;    -- own record -- check if Salary shows real value or masked 0.00
SELECT * FROM dbo.vw_AllBankOfficers;   -- expect: success -- Manager sees all Officers
SELECT * FROM dbo.vw_CustomerAll;       -- expect: success -- Manager sees all customer accounts
SELECT * FROM dbo.vw_AccountAll;        -- expect: success -- Manager sees all customer accounts (Confidentiality: "view all customer accounts")
SELECT * FROM dbo.vw_TransactionAll;    -- expect: success -- Manager sees all transactions
SELECT * FROM dbo.vw_PendingApprovalAll; -- expect: success -- Manager approves large transactions
SELECT * FROM dbo.vw_StaffDirectory;    -- expect: success -- name + contact, visible to all authenticated users

-- Manager manages staff (own proc, expect Success = 1)
DECLARE @ManageStaffSuccess BIT;
DECLARE @ManageStaffMessage NVARCHAR(200);

-- create a new Bank Officer -- proves only Bank Manager can manage staff details (Integrity requirement)
EXEC dbo.sp_ManageStaff
    @StaffName = 'Priya Devi',
    @Position  = 'Bank Officer',
    @Branch    = 'KL Branch',
    @Phone     = '0134444444',
    @Salary    = 4600.00,
    @Success   = @ManageStaffSuccess OUTPUT,
    @Message   = @ManageStaffMessage OUTPUT;

SELECT @ManageStaffSuccess AS Success, @ManageStaffMessage AS Message; -- expect Success = 1

EXEC dbo.sp_Logout;
REVERT;
GO

-- TEST: Officer (Farah Aina) re-checks vw_StaffOwnRecord now that a second officer (Priya Devi) exists
-- EXPECT: still exactly 1 row -- Farah Aina's own record only; the second query for Priya Devi's
--         name returns 0 rows, proving the view actually filters by StaffID rather than just
--         having nothing else around to leak
EXECUTE AS LOGIN = 'SmartBank_Officer';

DECLARE @Username NVARCHAR(50) = 'ofc_test';
DECLARE @Password NVARCHAR(50) = 'OfficerP@ss1!';

DECLARE @LoginSuccess    BIT;
DECLARE @PasswordExpired BIT;
DECLARE @LoginMessage    NVARCHAR(200);

EXEC dbo.sp_Login
    @Username        = @Username,
    @PlainPassword   = @Password,
    @Success         = @LoginSuccess    OUTPUT,
    @PasswordExpired = @PasswordExpired OUTPUT,
    @Message         = @LoginMessage    OUTPUT;

SELECT * FROM dbo.vw_StaffOwnRecord;                                 -- expect: 1 row, StaffName = 'Farah Aina'
SELECT * FROM dbo.vw_StaffOwnRecord WHERE StaffName = 'Priya Devi';   -- expect: 0 rows -- RLS hides the other officer's record

EXEC dbo.sp_Logout;
REVERT;
GO

-- TEST: Manager tries a Staff salary write, a direct transaction delete, DDL, and the
--       Officer-only sp_ManageCustomer -- run one line at a time
-- EXPECT: the UPDATE, DELETE, and CREATE TABLE are all denied; sp_ManageCustomer
--         returns Success = 0 (wrong role, not a permission error)
EXECUTE AS LOGIN = 'SmartBank_Manager';

DECLARE @Username NVARCHAR(50) = 'mgr_test';
DECLARE @Password NVARCHAR(50) = 'ManagerP@ss1!';

DECLARE @LoginSuccess    BIT;
DECLARE @PasswordExpired BIT;
DECLARE @LoginMessage    NVARCHAR(200);

EXEC dbo.sp_Login
    @Username        = @Username,
    @PlainPassword   = @Password,
    @Success         = @LoginSuccess    OUTPUT,
    @PasswordExpired = @PasswordExpired OUTPUT,
    @Message         = @LoginMessage    OUTPUT;

UPDATE dbo.Staff SET Salary = 999999;         -- expect: DENY -- salary changes go through sp_ManageStaff only
DELETE FROM dbo.TransactionRecord;            -- expect: DENY -- no direct writes to transaction data
CREATE TABLE dbo.Manager_Test_Table (ID INT); -- expect: DENY -- DDL should be DBA-only

DECLARE @UnauthorizedSuccess BIT;
DECLARE @UnauthorizedMessage NVARCHAR(200);

EXEC dbo.sp_ManageCustomer -- Officer-only proc -- expect Success = 0
    @CustomerName = 'Amir Hidayat',
    @ICNumber     = '123456789012',
    @Phone        = '0100000000',
    @Address      = 'X',
    @Success      = @UnauthorizedSuccess OUTPUT,
    @Message      = @UnauthorizedMessage OUTPUT;

EXEC dbo.sp_Logout;
REVERT;
GO

-- TEST: DBA logs in, creates and drops a table, then reads own-record views
-- EXPECT: CREATE TABLE / DROP TABLE both succeed (DBA is the only role granted
--         DDL); both SELECTs succeed and show only the DBA's own Staff row
EXECUTE AS LOGIN = 'SmartBank_DBA';

DECLARE @Username NVARCHAR(50) = 'dba_test';
DECLARE @Password NVARCHAR(50) = 'DbaTestP@ss1!';

DECLARE @LoginSuccess    BIT;
DECLARE @PasswordExpired BIT;
DECLARE @LoginMessage    NVARCHAR(200);

EXEC dbo.sp_Login
    @Username        = @Username,
    @PlainPassword   = @Password,
    @Success         = @LoginSuccess    OUTPUT,
    @PasswordExpired = @PasswordExpired OUTPUT,
    @Message         = @LoginMessage    OUTPUT;

CREATE TABLE dbo.DBA_Test_Table (ID INT); -- expect: ALLOW -- DBA is granted CREATE TABLE
DROP TABLE dbo.DBA_Test_Table;            -- clean up the table just created
SELECT * FROM dbo.vw_StaffOwnRecord;      -- expect: success -- DBA sees only their own record
SELECT * FROM dbo.vw_StaffDirectory;      -- expect: success -- name + contact, visible to all authenticated users

EXEC dbo.sp_Logout;
REVERT;
GO

-- TEST: DBA tries to read/write customer business data -- run one line at a time
-- EXPECT: all 3 statements are denied -- DBA manages schema/tables, not
--         customer or account data
EXECUTE AS LOGIN = 'SmartBank_DBA';

DECLARE @Username NVARCHAR(50) = 'dba_test';
DECLARE @Password NVARCHAR(50) = 'DbaTestP@ss1!';

DECLARE @LoginSuccess    BIT;
DECLARE @PasswordExpired BIT;
DECLARE @LoginMessage    NVARCHAR(200);

EXEC dbo.sp_Login
    @Username        = @Username,
    @PlainPassword   = @Password,
    @Success         = @LoginSuccess    OUTPUT,
    @PasswordExpired = @PasswordExpired OUTPUT,
    @Message         = @LoginMessage    OUTPUT;

SELECT * FROM dbo.Customer;                  -- expect: DENY -- DBA manages tables, not customer data
SELECT * FROM dbo.vw_CustomerAll;            -- expect: DENY -- same reasoning, via the view
UPDATE dbo.Account SET Balance = 999999;     -- expect: DENY -- DBA has no business-data write access

EXEC dbo.sp_Logout;
REVERT;
GO


-- ============================================================
-- STEP 4 of 9 -- ENCRYPTION (CLE)
-- Confidentiality: column-level encryption on Customer.ICNumber -- who can decrypt whose IC number
-- ============================================================

-- TEST: Officer calls sp_DecryptICNumber for Customer2
-- EXPECT: returns the decrypted IC number 990202021234 -- Officer/Manager are
--         allowed to decrypt any customer's IC number
DECLARE @Customer2ID INT = (SELECT CustomerID FROM dbo.UserLogin WHERE Username = 'cust2_test'); -- fetched as dbo before impersonating

EXECUTE AS LOGIN = 'SmartBank_Officer';

DECLARE @Username NVARCHAR(50) = 'ofc_test';
DECLARE @Password NVARCHAR(50) = 'OfficerP@ss1!';

DECLARE @LoginSuccess    BIT;
DECLARE @PasswordExpired BIT;
DECLARE @LoginMessage    NVARCHAR(200);

EXEC dbo.sp_Login
    @Username        = @Username,
    @PlainPassword   = @Password,
    @Success         = @LoginSuccess    OUTPUT,
    @PasswordExpired = @PasswordExpired OUTPUT,
    @Message         = @LoginMessage    OUTPUT;

-- Officer has no direct key access -- sp_DecryptICNumber opens/closes the key internally
EXEC dbo.sp_DecryptICNumber @CustomerID = @Customer2ID; -- expect decrypted value 990202021234

EXEC dbo.sp_Logout;
REVERT;
GO

-- TEST: Officer calls sp_DecryptOwnICNumber (a Customer-only proc)
-- EXPECT: denied -- this proc is granted to the Customer role only
EXECUTE AS LOGIN = 'SmartBank_Officer';

DECLARE @Username NVARCHAR(50) = 'ofc_test';
DECLARE @Password NVARCHAR(50) = 'OfficerP@ss1!';

DECLARE @LoginSuccess    BIT;
DECLARE @PasswordExpired BIT;
DECLARE @LoginMessage    NVARCHAR(200);

EXEC dbo.sp_Login
    @Username        = @Username,
    @PlainPassword   = @Password,
    @Success         = @LoginSuccess    OUTPUT,
    @PasswordExpired = @PasswordExpired OUTPUT,
    @Message         = @LoginMessage    OUTPUT;

EXEC dbo.sp_DecryptOwnICNumber; -- expect: DENY -- this proc is granted to Customer only, not Officer

EXEC dbo.sp_Logout;
REVERT;
GO

-- TEST: Customer2 calls sp_DecryptOwnICNumber
-- EXPECT: returns the decrypted IC number 990202021234 -- the proc reads
--         CustomerID from SESSION_CONTEXT, so it can only ever be their own
EXECUTE AS LOGIN = 'SmartBank_Customer';

DECLARE @Username NVARCHAR(50) = 'cust2_test';
DECLARE @Password NVARCHAR(50) = 'Customer2P@ss!';

DECLARE @LoginSuccess    BIT;
DECLARE @PasswordExpired BIT;
DECLARE @LoginMessage    NVARCHAR(200);

EXEC dbo.sp_Login
    @Username        = @Username,
    @PlainPassword   = @Password,
    @Success         = @LoginSuccess    OUTPUT,
    @PasswordExpired = @PasswordExpired OUTPUT,
    @Message         = @LoginMessage    OUTPUT;

-- proc reads CustomerID straight from SESSION_CONTEXT, so it can only ever decrypt the caller's own row
EXEC dbo.sp_DecryptOwnICNumber; -- expect decrypted value 990202021234

EXEC dbo.sp_Logout;
REVERT;
GO

-- TEST: Customer2 calls sp_DecryptICNumber (a Manager/Officer-only proc)
-- EXPECT: denied -- this proc is granted to Manager/Officer only
DECLARE @Customer2ID INT = (SELECT CustomerID FROM dbo.UserLogin WHERE Username = 'cust2_test'); -- fetched as dbo before impersonating

EXECUTE AS LOGIN = 'SmartBank_Customer';

DECLARE @Username NVARCHAR(50) = 'cust2_test';
DECLARE @Password NVARCHAR(50) = 'Customer2P@ss!';

DECLARE @LoginSuccess    BIT;
DECLARE @PasswordExpired BIT;
DECLARE @LoginMessage    NVARCHAR(200);

EXEC dbo.sp_Login
    @Username        = @Username,
    @PlainPassword   = @Password,
    @Success         = @LoginSuccess    OUTPUT,
    @PasswordExpired = @PasswordExpired OUTPUT,
    @Message         = @LoginMessage    OUTPUT;

EXEC dbo.sp_DecryptICNumber @CustomerID = @Customer2ID; -- expect: DENY -- this proc is granted to Manager/Officer only

EXEC dbo.sp_Logout;
REVERT;
GO


-- ============================================================
-- STEP 5 of 9 -- TRANSACTION INTEGRITY
-- Integrity: only Customers may transact, via sp_ProcessTransaction -- amount/ownership/overdraft rules
-- ============================================================

-- TEST: Customer2 deposits RM500 then withdraws RM100 from their own account
-- EXPECT: both calls return Success = 1; final Balance is 400.00
DECLARE @AccountID INT = (SELECT AccountID FROM dbo.Account WHERE CustomerID = (SELECT CustomerID FROM dbo.UserLogin WHERE Username = 'cust2_test')); -- fetched as dbo before impersonating

EXECUTE AS LOGIN = 'SmartBank_Customer';

DECLARE @Username NVARCHAR(50) = 'cust2_test';
DECLARE @Password NVARCHAR(50) = 'Customer2P@ss!';

DECLARE @LoginSuccess    BIT;
DECLARE @PasswordExpired BIT;
DECLARE @LoginMessage    NVARCHAR(200);

EXEC dbo.sp_Login
    @Username        = @Username,
    @PlainPassword   = @Password,
    @Success         = @LoginSuccess    OUTPUT,
    @PasswordExpired = @PasswordExpired OUTPUT,
    @Message         = @LoginMessage    OUTPUT;

DECLARE @TransactionSuccess BIT;
DECLARE @TransactionMessage NVARCHAR(200);

-- deposit RM500 into own account -- expect Success = 1, Balance becomes 500.00
EXEC dbo.sp_ProcessTransaction
    @AccountID       = @AccountID,
    @TransactionType = 'Deposit',
    @Amount          = 500.00,
    @Success         = @TransactionSuccess OUTPUT,
    @Message         = @TransactionMessage OUTPUT;
SELECT @TransactionSuccess AS Success, @TransactionMessage AS Message;

-- withdraw RM100 -- expect Success = 1, Balance becomes 400.00
EXEC dbo.sp_ProcessTransaction
    @AccountID       = @AccountID,
    @TransactionType = 'Withdrawal',
    @Amount          = 100.00,
    @Success         = @TransactionSuccess OUTPUT,
    @Message         = @TransactionMessage OUTPUT;
SELECT @TransactionSuccess AS Success, @TransactionMessage AS Message;

SELECT Balance FROM dbo.vw_AccountOwn WHERE AccountID = @AccountID; -- expect 400.00

EXEC dbo.sp_Logout;
REVERT;
GO

-- TEST: Customer2 tries an overdraft withdrawal, a negative deposit, and a
--       withdrawal from someone else's account
-- EXPECT: all 3 calls return Success = 0, each with a rule-specific message
--         (insufficient funds / invalid amount / not the account owner)
DECLARE @AccountID      INT = (SELECT AccountID FROM dbo.Account WHERE CustomerID = (SELECT CustomerID FROM dbo.UserLogin WHERE Username = 'cust2_test')); -- own account -- fetched as dbo before impersonating
DECLARE @OtherAccountID INT = (SELECT AccountID FROM dbo.Account WHERE CustomerID = (SELECT CustomerID FROM dbo.UserLogin WHERE Username = 'cust1_test')); -- someone else's account -- fetched as dbo before impersonating

EXECUTE AS LOGIN = 'SmartBank_Customer';

DECLARE @Username NVARCHAR(50) = 'cust2_test';
DECLARE @Password NVARCHAR(50) = 'Customer2P@ss!';

DECLARE @LoginSuccess    BIT;
DECLARE @PasswordExpired BIT;
DECLARE @LoginMessage    NVARCHAR(200);

EXEC dbo.sp_Login
    @Username        = @Username,
    @PlainPassword   = @Password,
    @Success         = @LoginSuccess    OUTPUT,
    @PasswordExpired = @PasswordExpired OUTPUT,
    @Message         = @LoginMessage    OUTPUT;

DECLARE @TransactionSuccess BIT;
DECLARE @TransactionMessage NVARCHAR(200);

-- try to withdraw far more than the balance
EXEC dbo.sp_ProcessTransaction
    @AccountID       = @AccountID,
    @TransactionType = 'Withdrawal',
    @Amount          = 999999999.00,
    @Success         = @TransactionSuccess OUTPUT,
    @Message         = @TransactionMessage OUTPUT;
SELECT @TransactionSuccess AS Success, @TransactionMessage AS Message; -- overdraft

-- try to deposit a negative amount
EXEC dbo.sp_ProcessTransaction
    @AccountID       = @AccountID,
    @TransactionType = 'Deposit',
    @Amount          = -50.00,
    @Success         = @TransactionSuccess OUTPUT,
    @Message         = @TransactionMessage OUTPUT;
SELECT @TransactionSuccess AS Success, @TransactionMessage AS Message; -- negative amount

-- try to withdraw from an account that isn't this customer's own
EXEC dbo.sp_ProcessTransaction
    @AccountID       = @OtherAccountID,
    @TransactionType = 'Withdrawal',
    @Amount          = 10.00,
    @Success         = @TransactionSuccess OUTPUT,
    @Message         = @TransactionMessage OUTPUT;
SELECT @TransactionSuccess AS Success, @TransactionMessage AS Message; -- not own account

EXEC dbo.sp_Logout;
REVERT;
GO

-- TEST: Customer2 deposits RM15,000 (above the RM10,000 approval threshold)
-- EXPECT: Success = 1, but the message says it's routed for Manager approval --
--         the deposit does not post to Balance yet
DECLARE @AccountID INT = (SELECT AccountID FROM dbo.Account WHERE CustomerID = (SELECT CustomerID FROM dbo.UserLogin WHERE Username = 'cust2_test')); -- fetched as dbo before impersonating

EXECUTE AS LOGIN = 'SmartBank_Customer';

DECLARE @Username NVARCHAR(50) = 'cust2_test';
DECLARE @Password NVARCHAR(50) = 'Customer2P@ss!';

DECLARE @LoginSuccess    BIT;
DECLARE @PasswordExpired BIT;
DECLARE @LoginMessage    NVARCHAR(200);

EXEC dbo.sp_Login
    @Username        = @Username,
    @PlainPassword   = @Password,
    @Success         = @LoginSuccess    OUTPUT,
    @PasswordExpired = @PasswordExpired OUTPUT,
    @Message         = @LoginMessage    OUTPUT;

DECLARE @TransactionSuccess BIT;
DECLARE @TransactionMessage NVARCHAR(200);

-- large deposit -- above the approval threshold, so it should land in PendingApproval, not post directly
EXEC dbo.sp_ProcessTransaction
    @AccountID       = @AccountID,
    @TransactionType = 'Deposit',
    @Amount          = 15000.00,
    @Success         = @TransactionSuccess OUTPUT,
    @Message         = @TransactionMessage OUTPUT;

SELECT @TransactionSuccess AS Success, @TransactionMessage AS Message; -- expect: routed for Manager approval

EXEC dbo.sp_Logout;
REVERT;
GO

-- TEST: Officer calls sp_ProcessTransaction on a customer's account
-- EXPECT: Success = 0 -- only the Customer role may call this proc
DECLARE @AccountID INT = (SELECT AccountID FROM dbo.Account WHERE CustomerID = (SELECT CustomerID FROM dbo.UserLogin WHERE Username = 'cust2_test')); -- fetched as dbo before impersonating

EXECUTE AS LOGIN = 'SmartBank_Officer';

DECLARE @Username NVARCHAR(50) = 'ofc_test';
DECLARE @Password NVARCHAR(50) = 'OfficerP@ss1!';

DECLARE @LoginSuccess    BIT;
DECLARE @PasswordExpired BIT;
DECLARE @LoginMessage    NVARCHAR(200);

EXEC dbo.sp_Login
    @Username        = @Username,
    @PlainPassword   = @Password,
    @Success         = @LoginSuccess    OUTPUT,
    @PasswordExpired = @PasswordExpired OUTPUT,
    @Message         = @LoginMessage    OUTPUT;

DECLARE @TransactionSuccess BIT;
DECLARE @TransactionMessage NVARCHAR(200);

-- Officer trying to transact on a customer's account -- only the Customer role may call this proc
EXEC dbo.sp_ProcessTransaction
    @AccountID       = @AccountID,
    @TransactionType = 'Deposit',
    @Amount          = 10.00,
    @Success         = @TransactionSuccess OUTPUT,
    @Message         = @TransactionMessage OUTPUT;

SELECT @TransactionSuccess AS Success, @TransactionMessage AS Message; -- expect Success = 0

EXEC dbo.sp_Logout;
REVERT;
GO

-- TEST: Manager approves the pending RM15,000 deposit request
-- EXPECT: Success = 1 -- only now does the deposit actually post to Balance
DECLARE @AccountID INT = (SELECT AccountID FROM dbo.Account WHERE CustomerID = (SELECT CustomerID FROM dbo.UserLogin WHERE Username = 'cust2_test')); -- fetched as dbo before impersonating

EXECUTE AS LOGIN = 'SmartBank_Manager';

DECLARE @Username NVARCHAR(50) = 'mgr_test';
DECLARE @Password NVARCHAR(50) = 'ManagerP@ss1!';

DECLARE @LoginSuccess    BIT;
DECLARE @PasswordExpired BIT;
DECLARE @LoginMessage    NVARCHAR(200);

EXEC dbo.sp_Login
    @Username        = @Username,
    @PlainPassword   = @Password,
    @Success         = @LoginSuccess    OUTPUT,
    @PasswordExpired = @PasswordExpired OUTPUT,
    @Message         = @LoginMessage    OUTPUT;

-- find the pending request created by the RM15,000 deposit above
DECLARE @RequestID INT = (
    SELECT TOP 1 RequestID
    FROM dbo.vw_PendingApprovalAll
    WHERE AccountID = @AccountID AND Status = 'Pending'
    ORDER BY RequestID DESC
);

DECLARE @ApproveSuccess BIT;
DECLARE @ApproveMessage NVARCHAR(200);

-- Manager approves it -- only now should the deposit actually post to Balance
EXEC dbo.sp_ApproveTransaction
    @RequestID = @RequestID,
    @Approve   = 1,
    @Success   = @ApproveSuccess OUTPUT,
    @Message   = @ApproveMessage OUTPUT;

SELECT @ApproveSuccess AS Success, @ApproveMessage AS Message; -- expect Success = 1

SELECT * FROM dbo.vw_PendingApprovalAll WHERE RequestID = @RequestID; -- expect: Status = 'Approved', ApprovedBy = mgr_test, ApprovalDate populated
SELECT * FROM dbo.vw_AccountAll WHERE AccountID = @AccountID;        -- expect: Balance now includes the approved RM15,000

EXEC dbo.sp_Logout;
REVERT;
GO

-- TEST: Customer2 transfers RM200 to Customer1's account
-- EXPECT: Success = 1; Customer2's balance drops to 15200.00 (15400 - 200)
DECLARE @FromAccountID INT = (SELECT AccountID FROM dbo.Account WHERE CustomerID = (SELECT CustomerID FROM dbo.UserLogin WHERE Username = 'cust2_test')); -- own account (source) -- fetched as dbo before impersonating
DECLARE @ToAccountID   INT = (SELECT AccountID FROM dbo.Account WHERE CustomerID = (SELECT CustomerID FROM dbo.UserLogin WHERE Username = 'cust1_test')); -- destination account -- fetched as dbo before impersonating

EXECUTE AS LOGIN = 'SmartBank_Customer';

DECLARE @Username NVARCHAR(50) = 'cust2_test';
DECLARE @Password NVARCHAR(50) = 'Customer2P@ss!';

DECLARE @LoginSuccess    BIT;
DECLARE @PasswordExpired BIT;
DECLARE @LoginMessage    NVARCHAR(200);

EXEC dbo.sp_Login
    @Username        = @Username,
    @PlainPassword   = @Password,
    @Success         = @LoginSuccess    OUTPUT,
    @PasswordExpired = @PasswordExpired OUTPUT,
    @Message         = @LoginMessage    OUTPUT;

DECLARE @TransactionSuccess BIT;
DECLARE @TransactionMessage NVARCHAR(200);

-- Customer2's balance is 15,400 by now (500 - 100 + the approved 15,000 deposit) -- comfortably covers this transfer
EXEC dbo.sp_ProcessTransaction
    @AccountID       = @FromAccountID,
    @TransactionType = 'Transfer',
    @Amount          = 200.00,
    @ToAccountID     = @ToAccountID,
    @Success         = @TransactionSuccess OUTPUT,
    @Message         = @TransactionMessage OUTPUT;

SELECT @TransactionSuccess AS Success, @TransactionMessage AS Message;  -- expect Success = 1
SELECT Balance FROM dbo.vw_AccountOwn WHERE AccountID = @FromAccountID; -- expect 15200.00 (15400 - 200)

EXEC dbo.sp_Logout;
REVERT;
GO

-- TEST: verify Customer1's account received the transfer (checked directly, not via RLS)
-- EXPECT: 250.00 (50.00 from Customer1's own earlier deposit + 200.00 transfer)
SELECT Balance FROM dbo.Account WHERE AccountID = (SELECT AccountID FROM dbo.Account WHERE CustomerID = (SELECT CustomerID FROM dbo.UserLogin WHERE Username = 'cust1_test')); -- destination account received the transfer
GO


-- ============================================================
-- STEP 6 of 9 -- AUDIT
-- Integrity: every valid AND rejected data change must be logged
-- EXPECT: first query returns every change made so far this session; second query is the
--         subset with ActionType = 'REJECTED'; third query shows status_desc = 'STARTED'
--         (native SQL Server Audit is active)
-- ============================================================

SELECT * FROM AuditSchema.AuditLog ORDER BY ChangeDate DESC;                              -- full audit trail so far
SELECT * FROM AuditSchema.AuditLog WHERE ActionType = 'REJECTED' ORDER BY ChangeDate DESC; -- just the denied/rejected attempts
SELECT name, status_desc FROM sys.dm_server_audit_status;                                 -- native SQL Server Audit is running
GO


-- ============================================================
-- STEP 7 of 9 -- TEMPORAL HISTORY / RECOVERY
-- Availability: accidental changes must be recoverable -- via system-versioned history + sp_RecoverX
-- ============================================================

-- TEST: simulate an accidental Phone change on Customer2's Customer row
-- EXPECT: the history view shows both the old and new Phone values, each with
--         its own SysStartTime/SysEndTime interval
DECLARE @CustomerID INT = (SELECT CustomerID FROM dbo.UserLogin WHERE Username = 'cust2_test');
WAITFOR DELAY '00:00:01';
UPDATE dbo.Customer SET Phone = '00000000000' WHERE CustomerID = @CustomerID;

-- TEST: DBA (a RecoveryAdmin member) restores Customer2's row to its pre-corruption state
-- EXPECT: Success = 1 -- the row's Phone reverts to its pre-corruption value
-- Merged into the same batch as the corruption above. AsOfDateTime is looked up from the
-- row's own history (SysStartTime of the version right before the corruption), per Lab 9's
-- "take note of the version history" approach -- not guessed as a fixed offset from now,
-- which only works if recovery happens within that exact window.
EXECUTE AS LOGIN = 'SmartBank_DBA';

DECLARE @Username NVARCHAR(50) = 'dba_test';
DECLARE @Password NVARCHAR(50) = 'DbaTestP@ss1!';

DECLARE @LoginSuccess    BIT;
DECLARE @PasswordExpired BIT;
DECLARE @LoginMessage    NVARCHAR(200);

EXEC dbo.sp_Login
    @Username        = @Username,
    @PlainPassword   = @Password,
    @Success         = @LoginSuccess    OUTPUT,
    @PasswordExpired = @PasswordExpired OUTPUT,
    @Message         = @LoginMessage    OUTPUT;

DECLARE @RecoverSuccess BIT;
DECLARE @RecoverMessage NVARCHAR(200);

-- the most recently closed history interval is the row's state right before the corruption
DECLARE @AsOfDateTime DATETIME2 = (
    SELECT TOP 1 SysStartTime
    FROM dbo.vw_Customer_History
    WHERE CustomerID = @CustomerID AND SysEndTime < '9999-12-31 23:59:59.9999999'
    ORDER BY SysEndTime DESC
);

-- restore the row to that looked-up point -- i.e. before the accidental Phone change
EXEC dbo.sp_RecoverCustomer
    @CustomerID   = @CustomerID,
    @AsOfDateTime = @AsOfDateTime,
    @Success      = @RecoverSuccess OUTPUT,
    @Message      = @RecoverMessage OUTPUT;

SELECT @RecoverSuccess AS Success, @RecoverMessage AS Message; -- expect Success = 1

EXEC dbo.sp_Logout;
REVERT;

-- TEST: verify the Phone value directly on the base table (outside any impersonation)
-- EXPECT: 0142222222 -- confirms the recovery actually wrote back to Customer
SELECT Phone FROM dbo.Customer WHERE CustomerID = (SELECT CustomerID FROM dbo.UserLogin WHERE Username = 'cust2_test'); -- Phone is restored
GO

-- TEST: Officer tries to read the Customer history view
-- EXPECT: denied -- history/recovery access is RecoveryAdmin-only
EXECUTE AS LOGIN = 'SmartBank_Officer';

DECLARE @Username NVARCHAR(50) = 'ofc_test';
DECLARE @Password NVARCHAR(50) = 'OfficerP@ss1!';

DECLARE @LoginSuccess    BIT;
DECLARE @PasswordExpired BIT;
DECLARE @LoginMessage    NVARCHAR(200);

EXEC dbo.sp_Login
    @Username        = @Username,
    @PlainPassword   = @Password,
    @Success         = @LoginSuccess    OUTPUT,
    @PasswordExpired = @PasswordExpired OUTPUT,
    @Message         = @LoginMessage    OUTPUT;

SELECT * FROM dbo.vw_Customer_History; -- expect: DENY -- history/recovery access is RecoveryAdmin-only

EXEC dbo.sp_Logout;
REVERT;
GO


-- TEST: Manager (not a RecoveryAdmin member) tries to call sp_RecoverCustomer
-- EXPECT: denied -- only RecoveryAdmin members (DBA) can run recovery procs
DECLARE @CustomerID INT = (SELECT CustomerID FROM dbo.UserLogin WHERE Username = 'cust2_test'); -- fetched as dbo before impersonating

EXECUTE AS LOGIN = 'SmartBank_Manager';

DECLARE @Username NVARCHAR(50) = 'mgr_test';
DECLARE @Password NVARCHAR(50) = 'ManagerP@ss1!';

DECLARE @LoginSuccess    BIT;
DECLARE @PasswordExpired BIT;
DECLARE @LoginMessage    NVARCHAR(200);

EXEC dbo.sp_Login
    @Username        = @Username,
    @PlainPassword   = @Password,
    @Success         = @LoginSuccess    OUTPUT,
    @PasswordExpired = @PasswordExpired OUTPUT,
    @Message         = @LoginMessage    OUTPUT;

DECLARE @RecoverSuccess BIT;
DECLARE @RecoverMessage NVARCHAR(200);
DECLARE @AsOfDateTime DATETIME2 = DATEADD(SECOND, -5, SYSUTCDATETIME());

-- Manager is not a RecoveryAdmin member, so this should be denied
EXEC dbo.sp_RecoverCustomer
    @CustomerID   = @CustomerID,
    @AsOfDateTime = @AsOfDateTime,
    @Success      = @RecoverSuccess OUTPUT,
    @Message      = @RecoverMessage OUTPUT;

EXEC dbo.sp_Logout;
REVERT;
GO

-- TEST: simulate an accidental Branch change on the Officer's Staff row
-- EXPECT: no output -- just sets up the corruption for the recovery below
DECLARE @OfficerStaffID INT = (SELECT StaffID FROM dbo.UserLogin WHERE Username = 'ofc_test');
WAITFOR DELAY '00:00:01';
UPDATE dbo.Staff SET Branch = 'WRONG BRANCH' WHERE StaffID = @OfficerStaffID; -- the "accidental" change

-- TEST: DBA restores the Officer's Staff row to its pre-corruption state (sp_RecoverStaff)
-- EXPECT: Success = 1
-- Merged into the same batch as the corruption above -- see note in the Customer2 Phone test.
EXECUTE AS LOGIN = 'SmartBank_DBA';

DECLARE @Username NVARCHAR(50) = 'dba_test';
DECLARE @Password NVARCHAR(50) = 'DbaTestP@ss1!';

DECLARE @LoginSuccess    BIT;
DECLARE @PasswordExpired BIT;
DECLARE @LoginMessage    NVARCHAR(200);

EXEC dbo.sp_Login
    @Username        = @Username,
    @PlainPassword   = @Password,
    @Success         = @LoginSuccess    OUTPUT,
    @PasswordExpired = @PasswordExpired OUTPUT,
    @Message         = @LoginMessage    OUTPUT;

DECLARE @RecoverSuccess BIT;
DECLARE @RecoverMessage NVARCHAR(200);

-- the most recently closed history interval is the row's state right before the corruption
DECLARE @AsOfDateTime DATETIME2 = (
    SELECT TOP 1 SysStartTime
    FROM dbo.vw_Staff_History
    WHERE StaffID = @OfficerStaffID AND SysEndTime < '9999-12-31 23:59:59.9999999'
    ORDER BY SysEndTime DESC
);

EXEC dbo.sp_RecoverStaff
    @StaffID      = @OfficerStaffID,
    @AsOfDateTime = @AsOfDateTime,
    @Success      = @RecoverSuccess OUTPUT,
    @Message      = @RecoverMessage OUTPUT;

SELECT @RecoverSuccess AS Success, @RecoverMessage AS Message; -- expect Success = 1

EXEC dbo.sp_Logout;
REVERT;

-- TEST: verify Branch directly on the base table
-- EXPECT: 'KL Branch' -- confirms sp_RecoverStaff wrote back correctly
SELECT Branch FROM dbo.Staff WHERE StaffID = (SELECT StaffID FROM dbo.UserLogin WHERE Username = 'ofc_test'); -- Branch is restored
GO

-- TEST: simulate an accidental Balance change on Customer1's account
-- EXPECT: no output -- just sets up the corruption for the recovery below
DECLARE @Customer1AccountID INT = (SELECT AccountID FROM dbo.Account WHERE CustomerID = (SELECT CustomerID FROM dbo.UserLogin WHERE Username = 'cust1_test'));
WAITFOR DELAY '00:00:01';
UPDATE dbo.Account SET Balance = 999999.00 WHERE AccountID = @Customer1AccountID; -- the "accidental" change

-- TEST: DBA restores Customer1's Account row to its pre-corruption state (sp_RecoverAccount)
-- EXPECT: Success = 1
-- Merged into the same batch as the corruption above -- see note in the Customer2 Phone test.
EXECUTE AS LOGIN = 'SmartBank_DBA';

DECLARE @Username NVARCHAR(50) = 'dba_test';
DECLARE @Password NVARCHAR(50) = 'DbaTestP@ss1!';

DECLARE @LoginSuccess    BIT;
DECLARE @PasswordExpired BIT;
DECLARE @LoginMessage    NVARCHAR(200);

EXEC dbo.sp_Login
    @Username        = @Username,
    @PlainPassword   = @Password,
    @Success         = @LoginSuccess    OUTPUT,
    @PasswordExpired = @PasswordExpired OUTPUT,
    @Message         = @LoginMessage    OUTPUT;

DECLARE @RecoverSuccess BIT;
DECLARE @RecoverMessage NVARCHAR(200);

-- the most recently closed history interval is the row's state right before the corruption
DECLARE @AsOfDateTime DATETIME2 = (
    SELECT TOP 1 SysStartTime
    FROM dbo.vw_Account_History
    WHERE AccountID = @Customer1AccountID AND SysEndTime < '9999-12-31 23:59:59.9999999'
    ORDER BY SysEndTime DESC
);

EXEC dbo.sp_RecoverAccount
    @AccountID    = @Customer1AccountID,
    @AsOfDateTime = @AsOfDateTime,
    @Success      = @RecoverSuccess OUTPUT,
    @Message      = @RecoverMessage OUTPUT;

SELECT @RecoverSuccess AS Success, @RecoverMessage AS Message; -- expect Success = 1

EXEC dbo.sp_Logout;
REVERT;

-- TEST: verify Balance directly on the base table
-- EXPECT: 250.00 -- confirms sp_RecoverAccount wrote back correctly (50.00 own
--         deposit + 200.00 transfer, the pre-corruption value)
SELECT Balance FROM dbo.Account WHERE AccountID = (SELECT AccountID FROM dbo.Account WHERE CustomerID = (SELECT CustomerID FROM dbo.UserLogin WHERE Username = 'cust1_test')); -- Balance is restored (50.00 own deposit + 200.00 transfer)
GO

-- TEST: simulate an accidental Amount change on Customer2's latest transaction (the Transfer)
-- EXPECT: no output -- just sets up the corruption for the recovery below
DECLARE @Customer1AccountID INT = (SELECT AccountID FROM dbo.Account WHERE CustomerID = (SELECT CustomerID FROM dbo.UserLogin WHERE Username = 'cust1_test'));
DECLARE @TargetTransID INT = (SELECT TOP 1 TransID FROM dbo.TransactionRecord WHERE AccountID = @Customer1AccountID ORDER BY TransID DESC); -- the Transfer performed earlier
WAITFOR DELAY '00:00:01';
UPDATE dbo.TransactionRecord SET Amount = 999999.00 WHERE TransID = @TargetTransID; -- the "accidental" change

-- TEST: DBA restores that TransactionRecord row to 5 seconds ago (sp_RecoverTransactionRecord)
-- EXPECT: Success = 1
-- Merged into the same batch as the corruption above -- see note in the Customer2 Phone test.
EXECUTE AS LOGIN = 'SmartBank_DBA';

DECLARE @Username NVARCHAR(50) = 'dba_test';
DECLARE @Password NVARCHAR(50) = 'DbaTestP@ss1!';

DECLARE @LoginSuccess    BIT;
DECLARE @PasswordExpired BIT;
DECLARE @LoginMessage    NVARCHAR(200);

EXEC dbo.sp_Login
    @Username        = @Username,
    @PlainPassword   = @Password,
    @Success         = @LoginSuccess    OUTPUT,
    @PasswordExpired = @PasswordExpired OUTPUT,
    @Message         = @LoginMessage    OUTPUT;

DECLARE @RecoverSuccess BIT;
DECLARE @RecoverMessage NVARCHAR(200);

-- the most recently closed history interval is the row's state right before the corruption
DECLARE @AsOfDateTime DATETIME2 = (
    SELECT TOP 1 SysStartTime
    FROM dbo.vw_TransactionRecord_History
    WHERE TransID = @TargetTransID AND SysEndTime < '9999-12-31 23:59:59.9999999'
    ORDER BY SysEndTime DESC
);

EXEC dbo.sp_RecoverTransactionRecord
    @TransID      = @TargetTransID,
    @AsOfDateTime = @AsOfDateTime,
    @Success      = @RecoverSuccess OUTPUT,
    @Message      = @RecoverMessage OUTPUT;

SELECT @RecoverSuccess AS Success, @RecoverMessage AS Message; -- expect Success = 1

EXEC dbo.sp_Logout;
REVERT;

-- TEST: verify Amount directly on the base table
-- EXPECT: 200.00 -- confirms sp_RecoverTransactionRecord wrote back correctly
SELECT Amount FROM dbo.TransactionRecord WHERE TransID = (
    SELECT TOP 1 TransID FROM dbo.TransactionRecord
    WHERE AccountID = (SELECT AccountID FROM dbo.Account WHERE CustomerID = (SELECT CustomerID FROM dbo.UserLogin WHERE Username = 'cust1_test'))
    ORDER BY TransID DESC
); -- Amount is restored
GO

-- ============================================================
-- STEP 8 of 9 -- BACKUP AUTOMATION
-- Availability: Full/Differential/Log backups + a defined RPO via SQL Server Agent jobs
-- ============================================================

-- TEST: run all three backup procs
-- EXPECT: no errors -- each writes a .bak/.trn file to its configured folder
--         (check C:\SQLBackups\Full, \Differential, \Log if you want to confirm on disk)
EXEC dbo.sp_PerformFullBackup;         -- writes a .bak to C:\SQLBackups\Full\
EXEC dbo.sp_PerformDifferentialBackup; -- writes a .bak to C:\SQLBackups\Differential\
EXEC dbo.sp_PerformLogBackup;          -- writes a .trn to C:\SQLBackups\Log\ (only valid under FULL recovery model)
GO

-- TEST: check the SQL Server Agent jobs/schedules and the database recovery model
-- EXPECT: 3 enabled jobs matching 'SmartBankDB - %Backup%', each with a schedule;
--         recovery_model_desc = FULL (required for log backups to work at all)
SELECT
    j.name,
    j.enabled,
    s.name AS ScheduleName,
    s.freq_subday_type,
    s.freq_subday_interval
FROM msdb.dbo.sysjobs j
LEFT JOIN msdb.dbo.sysjobschedules js ON j.job_id = js.job_id
LEFT JOIN msdb.dbo.sysschedules   s  ON js.schedule_id = s.schedule_id
WHERE j.name LIKE N'SmartBankDB - %Backup%';

SELECT recovery_model_desc FROM sys.databases WHERE name = 'SmartBankDB'; -- expect FULL -- required for log backups to work at all
GO


-- ============================================================
-- STEP 9 of 9 -- DDL TRIGGER: trg_PreventVersioningDisable
-- Integrity: blocks turning off temporal history, which would silently break recovery
-- EXPECT: the ALTER TABLE fails with a custom error and is rolled back -- even DBA,
--         who otherwise has full DDL rights, cannot disable SYSTEM_VERSIONING
-- Run this block alone -- if the trigger's ROLLBACK fires it can abort the rest of a batch.
-- ============================================================

EXECUTE AS LOGIN = 'SmartBank_DBA';

DECLARE @Username NVARCHAR(50) = 'dba_test';
DECLARE @Password NVARCHAR(50) = 'DbaTestP@ss1!';

DECLARE @LoginSuccess    BIT;
DECLARE @PasswordExpired BIT;
DECLARE @LoginMessage    NVARCHAR(200);

EXEC dbo.sp_Login
    @Username        = @Username,
    @PlainPassword   = @Password,
    @Success         = @LoginSuccess    OUTPUT,
    @PasswordExpired = @PasswordExpired OUTPUT,
    @Message         = @LoginMessage    OUTPUT;

-- even DBA (who has CREATE TABLE / ALTER rights) cannot switch versioning off -- the DDL trigger rolls this back
ALTER TABLE dbo.Staff SET (SYSTEM_VERSIONING = OFF); -- expect: blocked with a custom error

EXEC dbo.sp_Logout;
REVERT;
GO