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