CREATE DATABASE SmartBankDB;
GO

USE SmartBankDB;
GO

-- =============================================
-- Staff Table (temporal)
-- =============================================
CREATE TABLE Staff (
    StaffID   INT  NOT NULL IDENTITY(1,1) PRIMARY KEY,
    StaffName NVARCHAR(100)  NOT NULL,
    Position  NVARCHAR(50)   NOT NULL
        CONSTRAINT CHK_Position
        CHECK (Position IN ('DBA', 'Bank Manager', 'Bank Officer')),
    Branch    NVARCHAR(100)  NOT NULL,
    Phone     NVARCHAR(20)   NOT NULL,
    Salary    DECIMAL(15,2)  NOT NULL
        CONSTRAINT CHK_Salary
        CHECK (Salary > 0),
    IsActive  BIT NOT NULL DEFAULT 1,
    SysStartTime DATETIME2 GENERATED ALWAYS AS ROW START HIDDEN NOT NULL
        DEFAULT SYSUTCDATETIME(),
    SysEndTime   DATETIME2 GENERATED ALWAYS AS ROW END   HIDDEN NOT NULL
        DEFAULT CONVERT(DATETIME2, '9999-12-31 23:59:59.9999999'),
    PERIOD FOR SYSTEM_TIME (SysStartTime, SysEndTime)
)
WITH (SYSTEM_VERSIONING = ON (HISTORY_TABLE = dbo.Staff_History));
GO

-- =============================================
-- Customer Table (temporal)
-- =============================================
CREATE TABLE Customer (
    CustomerID   INT NOT NULL IDENTITY(1,1) PRIMARY KEY,
    CustomerName NVARCHAR(100) NOT NULL,
    ICNumber     VARBINARY(MAX)  NOT NULL,
    ICNumberHash VARBINARY(32)   NOT NULL UNIQUE,
    Phone        NVARCHAR(20)    NOT NULL,
    Address      NVARCHAR(255)   NOT NULL,
    IsActive     BIT             NOT NULL DEFAULT 1,
    SysStartTime DATETIME2 GENERATED ALWAYS AS ROW START HIDDEN NOT NULL
        DEFAULT SYSUTCDATETIME(),
    SysEndTime   DATETIME2 GENERATED ALWAYS AS ROW END   HIDDEN NOT NULL
        DEFAULT CONVERT(DATETIME2, '9999-12-31 23:59:59.9999999'),
    PERIOD FOR SYSTEM_TIME (SysStartTime, SysEndTime)
)
WITH (SYSTEM_VERSIONING = ON (HISTORY_TABLE = dbo.Customer_History));
GO

-- =============================================
-- Account Table (temporal)
-- =============================================
CREATE TABLE Account (
    AccountID  INT  NOT NULL IDENTITY(1,1) PRIMARY KEY,
    CustomerID  INT NOT NULL,
    AccountType NVARCHAR(20)  NOT NULL
        CONSTRAINT CHK_AccountType
        CHECK (AccountType IN ('Savings', 'Current', 'Fixed Deposit')),
    Balance     DECIMAL(15,2)  NOT NULL DEFAULT 0.00
        CONSTRAINT CHK_Balance
        CHECK (Balance >= 0),
    IsActive BIT NOT NULL DEFAULT 1,
    SysStartTime DATETIME2 GENERATED ALWAYS AS ROW START HIDDEN NOT NULL
        DEFAULT SYSUTCDATETIME(),
    SysEndTime   DATETIME2 GENERATED ALWAYS AS ROW END   HIDDEN NOT NULL
        DEFAULT CONVERT(DATETIME2, '9999-12-31 23:59:59.9999999'),
    PERIOD FOR SYSTEM_TIME (SysStartTime, SysEndTime),
    CONSTRAINT FK_Account_Customer
        FOREIGN KEY (CustomerID) REFERENCES Customer(CustomerID)
        ON DELETE NO ACTION
        ON UPDATE NO ACTION
)
WITH (SYSTEM_VERSIONING = ON (HISTORY_TABLE = dbo.Account_History));
GO

-- =============================================
-- TransactionRecord Table (temporal)
-- =============================================
CREATE TABLE TransactionRecord (
    TransID         INT IDENTITY(1,1)  NOT NULL PRIMARY KEY,
    AccountID       INT                NOT NULL,
    TransDate       DATETIME2          NOT NULL DEFAULT SYSDATETIME(),
    Amount          DECIMAL(15,2)      NOT NULL
        CONSTRAINT CHK_Amount
        CHECK (Amount > 0),
    TransactionType NVARCHAR(20)       NOT NULL
        CONSTRAINT CHK_TransactionType
        CHECK (TransactionType IN ('Deposit', 'Withdrawal', 'Transfer')),
    ToAccountID INT NULL,
    SysStartTime DATETIME2 GENERATED ALWAYS AS ROW START HIDDEN NOT NULL
        DEFAULT SYSUTCDATETIME(),
    SysEndTime   DATETIME2 GENERATED ALWAYS AS ROW END   HIDDEN NOT NULL
        DEFAULT CONVERT(DATETIME2, '9999-12-31 23:59:59.9999999'),
    PERIOD FOR SYSTEM_TIME (SysStartTime, SysEndTime),
    CONSTRAINT CHK_TransferNotSelf_TR
        CHECK (ToAccountID IS NULL OR ToAccountID <> AccountID),
    CONSTRAINT CHK_TransactionToAccountConsistency        -- NEW
        CHECK (
            (TransactionType = 'Transfer' AND ToAccountID IS NOT NULL)
            OR
            (TransactionType IN ('Deposit', 'Withdrawal') AND ToAccountID IS NULL)
        ),
    CONSTRAINT FK_Transaction_Account
        FOREIGN KEY (AccountID) REFERENCES Account(AccountID)
        ON DELETE NO ACTION
        ON UPDATE NO ACTION,
    CONSTRAINT FK_Transaction_ToAccount
        FOREIGN KEY (ToAccountID) REFERENCES Account(AccountID)
        ON DELETE NO ACTION
        ON UPDATE NO ACTION
)
WITH (SYSTEM_VERSIONING = ON (HISTORY_TABLE = dbo.TransactionRecord_History));
GO

-- =============================================
-- UserLogin Table
-- =============================================
CREATE TABLE UserLogin (
    LoginID      INT            NOT NULL IDENTITY(1,1) PRIMARY KEY,
    Username     NVARCHAR(50)   NOT NULL UNIQUE,
    PasswordHash VARBINARY(64)  NOT NULL,
    Salt         VARBINARY(32)  NOT NULL,
    StaffID      INT            NULL,
    CustomerID   INT            NULL,
    UserType     NVARCHAR(10)   NOT NULL,
    CreatedDate  DATETIME2      NOT NULL DEFAULT SYSDATETIME(),
    LastLogin    DATETIME2      NULL,
    FailedLoginAttempts INT     NOT NULL DEFAULT 0,
    LockoutUntil DATETIME2      NULL,
    IsActive     BIT            NOT NULL DEFAULT 1,
    CONSTRAINT CHK_UserType
        CHECK (
            (UserType = 'Staff'    AND StaffID IS NOT NULL AND CustomerID IS NULL)
            OR
            (UserType = 'Customer' AND CustomerID IS NOT NULL AND StaffID IS NULL)
        ),
    CONSTRAINT FK_UserLogin_Staff
        FOREIGN KEY (StaffID) REFERENCES Staff(StaffID)
        ON DELETE NO ACTION
        ON UPDATE NO ACTION,
    CONSTRAINT FK_UserLogin_Customer
        FOREIGN KEY (CustomerID) REFERENCES Customer(CustomerID)
        ON DELETE NO ACTION
        ON UPDATE NO ACTION
);
GO

CREATE UNIQUE INDEX UQ_StaffLogin
    ON UserLogin(StaffID)
    WHERE StaffID IS NOT NULL;
GO

CREATE UNIQUE INDEX UQ_CustomerLogin
    ON UserLogin(CustomerID)
    WHERE CustomerID IS NOT NULL;
GO

-- =============================================
-- AuditLog Table
-- =============================================
CREATE TABLE AuditLog (
    LogID      BIGINT IDENTITY(1,1)  NOT NULL PRIMARY KEY,
    TableName  NVARCHAR(128)         NOT NULL,
    ColumnName NVARCHAR(128)         NULL,
    OldValue   NVARCHAR(MAX)         NULL,
    NewValue   NVARCHAR(MAX)         NULL,
    ChangedBy  NVARCHAR(50)          NOT NULL,
    ActionType NVARCHAR(10)          NOT NULL
        CONSTRAINT CHK_ActionType
        CHECK (ActionType IN ('INSERT', 'UPDATE', 'DELETE', 'REJECTED')),
    ChangeDate DATETIME2  NOT NULL DEFAULT SYSDATETIME()
);
GO

-- =============================================
-- PendingApproval Table
-- =============================================
CREATE TABLE PendingApproval (
    RequestID       INT IDENTITY(1,1)  NOT NULL PRIMARY KEY,
    AccountID       INT                NOT NULL,
    RequestedBy     NVARCHAR(50)       NOT NULL,
    ApprovedBy      NVARCHAR(50)       NULL,
    Amount          DECIMAL(15,2)      NOT NULL
        CONSTRAINT CHK_ApprovalAmount
        CHECK (Amount > 0),
    TransactionType NVARCHAR(20) NOT NULL
        CONSTRAINT CHK_PendingTransType
        CHECK (TransactionType IN ('Deposit', 'Withdrawal', 'Transfer')),
    ToAccountID INT NULL,
    Status  NVARCHAR(10)  NOT NULL DEFAULT 'Pending'
        CONSTRAINT CHK_ApprovalStatus
        CHECK (Status IN ('Pending', 'Approved', 'Rejected')),
    RequestDate DATETIME2 NOT NULL DEFAULT SYSDATETIME(),
    ApprovalDate  DATETIME2  NULL,
    CONSTRAINT CHK_TransferNotSelf_PA
        CHECK (ToAccountID IS NULL OR ToAccountID <> AccountID),
    CONSTRAINT CHK_PendingApprovalToAccountConsistency    -- NEW
        CHECK (
            (TransactionType = 'Transfer' AND ToAccountID IS NOT NULL)
            OR
            (TransactionType IN ('Deposit', 'Withdrawal') AND ToAccountID IS NULL)
        ),
    CONSTRAINT CHK_ApprovalConsistency
        CHECK (
            (Status = 'Pending' AND ApprovalDate IS NULL AND ApprovedBy IS NULL)
            OR
            (Status IN ('Approved', 'Rejected') AND ApprovalDate IS NOT NULL AND ApprovedBy IS NOT NULL)
        ),
    CONSTRAINT FK_PendingApproval_Account
        FOREIGN KEY (AccountID) REFERENCES Account(AccountID)
        ON DELETE NO ACTION
        ON UPDATE NO ACTION,
    CONSTRAINT FK_PendingApproval_ToAccount
        FOREIGN KEY (ToAccountID) REFERENCES Account(AccountID)
        ON DELETE NO ACTION
        ON UPDATE NO ACTION,
    CONSTRAINT FK_PendingApproval_RequestedBy             -- NEW
        FOREIGN KEY (RequestedBy) REFERENCES UserLogin(Username)
        ON DELETE NO ACTION
        ON UPDATE NO ACTION,
    CONSTRAINT FK_PendingApproval_ApprovedBy              -- NEW
        FOREIGN KEY (ApprovedBy) REFERENCES UserLogin(Username)
        ON DELETE NO ACTION
        ON UPDATE NO ACTION
);
GO

-- =============================================
--                SEED DATA SECTION
-- Demo data for Staff, Customer, Account, UserLogin,
-- TransactionRecord, PendingApproval. ICNumber/PasswordHash
-- use placeholder encryption/hashing pending C's final approach.
-- =============================================

-- =============================================
-- Staff: 1 DBA, 5 Manager, 10 Officer (16 total)
-- Officer #10 (Officer_Inactive) is soft-deleted to prove deactivation
-- =============================================
INSERT INTO Staff (StaffName, Position, Branch, Phone, Salary, IsActive) VALUES
('Aisha Rahman',      'DBA',           'HQ',           '0121234567', 9500.00, 1),
('Farid Osman',       'Bank Manager',  'Kuala Lumpur', '0122345678', 8200.00, 1),
('Mei Ling Tan',      'Bank Manager',  'Petaling Jaya','0123456789', 8200.00, 1),
('Ravi Kumar',        'Bank Manager',  'Subang',       '0124567890', 8200.00, 1),
('Nurul Aina',        'Bank Manager',  'Klang',        '0125678901', 8200.00, 1),
('Wei Jian Lim',      'Bank Manager',  'Shah Alam',    '0126789012', 8200.00, 1),
('Hafiz Zainal',      'Bank Officer',  'Kuala Lumpur', '0127890123', 4500.00, 1),
('Siti Aminah',       'Bank Officer',  'Kuala Lumpur', '0128901234', 4500.00, 1),
('Kevin Wong',        'Bank Officer',  'Petaling Jaya','0129012345', 4500.00, 1),
('Priya Sharma',      'Bank Officer',  'Petaling Jaya','0121122334', 4500.00, 1),
('Amir Hakim',        'Bank Officer',  'Subang',       '0122233445', 4500.00, 1),
('Chong Wei Ling',    'Bank Officer',  'Subang',       '0123344556', 4500.00, 1),
('Nabila Yusof',      'Bank Officer',  'Klang',        '0124455667', 4500.00, 1),
('Daniel Lee',        'Bank Officer',  'Klang',        '0125566778', 4500.00, 1),
('Fatimah Zahra',     'Bank Officer',  'Shah Alam',    '0126677889', 4500.00, 1),
('Officer Inactive',  'Bank Officer',  'Shah Alam',    '0127788990', 4500.00, 0);
GO

-- =============================================
-- Customer: 20 total. CustomerID 1 is inactive (soft-deleted).
-- CustomerID 2 and 3 will each receive a second account below (multi-account proof).
-- ICNumber/ICNumberHash use PLACEHOLDER encryption -- flagged for C to replace.
-- =============================================
DECLARE @ICPlaceholders TABLE (RowNum INT IDENTITY(1,1), PlainIC NVARCHAR(20));
INSERT INTO @ICPlaceholders (PlainIC) VALUES
('900101101234'),('880215102345'),('920330103456'),('851122104567'),('930618105678'),
('870704106789'),('960912107890'),('890825108901'),('941117109012'),('861005110123'),
('991230111234'),('840301112345'),('950419113456'),('920607114567'),('880814115678'),
('970126116789'),('901009117890'),('930523118901'),('861211119012'),('941003120123');

DECLARE @CustNames TABLE (RowNum INT IDENTITY(1,1), CustomerName NVARCHAR(100), Phone NVARCHAR(20), Address NVARCHAR(255), IsActive BIT);
INSERT INTO @CustNames (CustomerName, Phone, Address, IsActive) VALUES
('Customer Inactive',  '0131234567', 'No 1, Jalan Damai, Kuala Lumpur',        0),
('Aiman Haziq',        '0132345678', 'No 2, Jalan Bunga, Petaling Jaya',       1),
('Grace Lim',          '0133456789', 'No 3, Jalan Mawar, Subang Jaya',         1),
('Suresh Nair',        '0134567890', 'No 4, Jalan Indah, Klang',               1),
('Nadia Iskandar',     '0135678901', 'No 5, Jalan Sentosa, Shah Alam',         1),
('Benjamin Teh',       '0136789012', 'No 6, Jalan Harmoni, Kuala Lumpur',      1),
('Farah Diyana',       '0137890123', 'No 7, Jalan Ceria, Petaling Jaya',       1),
('Vincent Chua',       '0138901234', 'No 8, Jalan Aman, Subang Jaya',          1),
('Hana Batrisyia',     '0139012345', 'No 9, Jalan Maju, Klang',                1),
('Arjun Singh',        '0131122334', 'No 10, Jalan Bahagia, Shah Alam',        1),
('Zara Iman',          '0132233445', 'No 11, Jalan Sejahtera, Kuala Lumpur',   1),
('Marcus Ong',         '0133344556', 'No 12, Jalan Damansara, Petaling Jaya',  1),
('Aleesha Putri',      '0134455667', 'No 13, Jalan Kenanga, Subang Jaya',      1),
('Jason Yap',          '0135566778', 'No 14, Jalan Melur, Klang',              1),
('Insyirah Aqilah',    '0136677889', 'No 15, Jalan Angsana, Shah Alam',        1),
('Michael Fernandez',  '0137788990', 'No 16, Jalan Cempaka, Kuala Lumpur',     1),
('Aina Sofea',         '0138899001', 'No 17, Jalan Teratai, Petaling Jaya',    1),
('Dinesh Kumar',       '0139900112', 'No 18, Jalan Dahlia, Subang Jaya',       1),
('Qistina Balqis',     '0131234098', 'No 19, Jalan Anggerik, Klang',           1),
('Ethan Goh',          '0132345109', 'No 20, Jalan Kasturi, Shah Alam',        1);

INSERT INTO Customer (CustomerName, ICNumber, ICNumberHash, Phone, Address, IsActive)
SELECT
    c.CustomerName,
    ENCRYPTBYPASSPHRASE('TEMP_PLACEHOLDER_KEY', i.PlainIC),   -- placeholder, C to re-encrypt with real cert/key
    HASHBYTES('SHA2_256', i.PlainIC),
    c.Phone,
    c.Address,
    c.IsActive
FROM @CustNames c
JOIN @ICPlaceholders i ON i.RowNum = c.RowNum
ORDER BY c.RowNum;
GO

-- =============================================
-- Account: 24 total. CustomerID 2 and 3 each get 2 accounts (multi-account proof).
-- CustomerID 1 (inactive) still gets 1 account for completeness of the deactivation demo.
-- =============================================
INSERT INTO Account (CustomerID, AccountType, Balance, IsActive) VALUES
(1,  'Savings', 500.00,   0),
(2,  'Savings', 3200.00,  1),
(2,  'Current', 1500.00,  1),
(3,  'Savings', 8700.00,  1),
(3,  'Fixed Deposit', 15000.00, 1),
(4,  'Savings', 2100.00,  1),
(5,  'Current', 900.00,   1),
(6,  'Savings', 4300.00,  1),
(7,  'Savings', 1750.00,  1),
(8,  'Current', 6200.00,  1),
(9,  'Savings', 3400.00,  1),
(10, 'Savings', 2950.00,  1),
(11, 'Current', 5100.00,  1),
(12, 'Savings', 800.00,   1),
(13, 'Savings', 12500.00, 1),
(14, 'Current', 1900.00,  1),
(15, 'Savings', 3600.00,  1),
(16, 'Savings', 700.00,   1),
(17, 'Current', 4400.00,  1),
(18, 'Savings', 2200.00,  1),
(19, 'Savings', 9800.00,  1),
(20, 'Current', 1300.00,  1),
(2,  'Fixed Deposit', 20000.00, 1),
(3,  'Current', 2600.00, 1);
GO

-- =============================================
-- UserLogin: 1 per Staff (16) + 1 per Customer (20) = 36
-- PasswordHash/Salt are PLACEHOLDER -- to be replaced once C/B finalize real hashing
-- IsActive mirrors the linked Staff/Customer IsActive status
-- =============================================
DECLARE @LoginSeed TABLE (RowNum INT IDENTITY(1,1), Username NVARCHAR(50), StaffID INT NULL, CustomerID INT NULL, UserType NVARCHAR(10), IsActive BIT);

INSERT INTO @LoginSeed (Username, StaffID, UserType, IsActive)
SELECT 'staff_' + LOWER(REPLACE(StaffName, ' ', '')), StaffID, 'Staff', IsActive
FROM Staff;

INSERT INTO @LoginSeed (Username, CustomerID, UserType, IsActive)
SELECT 'cust_' + LOWER(REPLACE(CustomerName, ' ', '')), CustomerID, 'Customer', IsActive
FROM Customer;

INSERT INTO UserLogin (Username, PasswordHash, Salt, StaffID, CustomerID, UserType, FailedLoginAttempts, LockoutUntil, IsActive)
SELECT
    Username,
    HASHBYTES('SHA2_512', CONVERT(NVARCHAR(50), NEWID())),  -- placeholder hash, replace with real hashing procedure output
    HASHBYTES('SHA2_256', CONVERT(NVARCHAR(50), NEWID())),  -- placeholder salt
    StaffID,
    CustomerID,
    UserType,
    0,
    NULL,
    IsActive
FROM @LoginSeed;
GO

-- Demo-ready credentials (memorable, for live login during Step 1) --
-- DBA:     staff_aisharahman
-- Manager: staff_faridosman, staff_meilingtan
-- Officer: staff_hafizzainal, staff_sitiaminah
-- Customer: cust_aimanhaziq, cust_gracelim
-- Actual passwords to be set once real hashing (sp_ChangePassword / registration) is wired up.

-- =============================================
-- TransactionRecord: bulk filler (~180 rows) across the 24 accounts
-- Plus explicit transfers between seeded customers' accounts
-- =============================================

-- Explicit transfers (Aiman -> Grace, Grace -> Aiman) for believable audit trail
INSERT INTO TransactionRecord (AccountID, Amount, TransactionType, ToAccountID) VALUES
(2, 500.00, 'Transfer', 4),   -- Aiman's Savings -> Grace's Savings
(4, 200.00, 'Transfer', 2),   -- Grace's Savings -> Aiman's Savings
(3, 1000.00, 'Transfer', 5),  -- Aiman's Current -> Grace's Fixed Deposit
(9, 350.00, 'Transfer', 11),  -- Farah -> Hana
(13, 800.00, 'Transfer', 17); -- Zara -> Insyirah
GO

-- Bulk filler: random deposits/withdrawals across AccountID 1-24, excluding closed/invalid combos
DECLARE @i INT = 1;
DECLARE @AcctID INT;
DECLARE @Amt DECIMAL(15,2);
DECLARE @Type NVARCHAR(20);

WHILE @i <= 180
BEGIN
    SET @AcctID = (ABS(CHECKSUM(NEWID())) % 24) + 1;     -- AccountID 1-24
    SET @Amt = CAST((ABS(CHECKSUM(NEWID())) % 500000) / 100.0 + 10.00 AS DECIMAL(15,2));  -- RM10 - RM5010
    SET @Type = CASE WHEN ABS(CHECKSUM(NEWID())) % 2 = 0 THEN 'Deposit' ELSE 'Withdrawal' END;

    INSERT INTO TransactionRecord (AccountID, Amount, TransactionType, ToAccountID)
    VALUES (@AcctID, @Amt, @Type, NULL);

    SET @i += 1;
END
GO

-- =============================================
-- PendingApproval: 1 pre-existing large transaction (>RM10,000) sitting Pending
-- NOTE: once sp_ProcessTransaction (Section 4.x) exists, regenerate this row by
-- calling the real procedure instead of a direct INSERT, so the audit trail is honest.
-- Requires UserLogin to exist first (FK to Username).
-- =============================================
INSERT INTO PendingApproval (AccountID, RequestedBy, Amount, TransactionType, ToAccountID, Status)
VALUES (15, 'staff_hafizzainal', 15000.00, 'Withdrawal', NULL, 'Pending');
GO