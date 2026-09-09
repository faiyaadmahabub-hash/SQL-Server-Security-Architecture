-- SmartBankDB Codebase: schema, roles, views, procedures, triggers, backup automation. Covers Confidentiality + Integrity + Availability. Seed data and tests live in FeatureTests.sql; demo script in DemoWalkthrough.sql. BEFORE RUNNING: create C:\SQLAudit\, C:\SQLKeys\, C:\SQLBackups\Full\, C:\SQLBackups\Differential\, C:\SQLBackups\Log\ with service-account write access; SQL Server Agent must be running.


-- Parts: 0 Baseline | 1 Authentication/Hashing | 2 RBAC | 3 Views/DDM | 4 Row Filtering | 5 Native + Login Audit | 6 Encryption | 6B Static Masking/Anonymisation | 7 DML Audit Triggers | 8 Write Procedures | 9 Recovery | 10 Backup Automation.
-- RecoveryAdmin (Part 2): 5th role holding recovery/history access, DBA nested as member -- keeps DBA's own grants matching the rubric literally. Integrity + Availability.


-- ################################################################
-- ## PART 0 -- DATABASE & TABLE BASELINE  (SQL_Database_Security_Baseline.sql)
-- ################################################################

CREATE DATABASE SmartBankDB;
GO

USE SmartBankDB;
GO

-- Staff table (temporal).
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

-- Customer table (temporal).
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

-- Account table (temporal).
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

-- TransactionRecord table (temporal).
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

-- Dynamic Data Masking (DDM): protects sensitive attributes while preserving controlled access through views/RLS.
-- Customers must be able to access their own information; therefore ownership is handled by RLS, not by hiding their own profile.
ALTER TABLE dbo.Staff
ALTER COLUMN Salary ADD MASKED WITH (FUNCTION = 'default()');
GO

ALTER TABLE dbo.Customer
ALTER COLUMN Phone 
ADD MASKED WITH (FUNCTION = 'partial(0,"XXXX",4)');
GO

ALTER TABLE dbo.Customer
ALTER COLUMN Address ADD MASKED WITH (FUNCTION = 'default()');
GO

-- C1: Account balances are masked by default. Managers and customers receive
-- narrowly scoped UNMASK rights later, after the database roles exist.
ALTER TABLE dbo.Account
ALTER COLUMN Balance ADD MASKED WITH (FUNCTION = 'default()');
GO

-- UserLogin table.
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

-- AuditLog table: lives in AuditSchema (not dbo) so DBA's table-management rights never reach it. Integrity.
CREATE SCHEMA AuditSchema AUTHORIZATION dbo;
GO

CREATE TABLE AuditSchema.AuditLog (
    LogID      BIGINT IDENTITY(1,1)  NOT NULL PRIMARY KEY,
    TableName  NVARCHAR(128)         NOT NULL,
    ColumnName NVARCHAR(128)         NULL,
    RecordID   NVARCHAR(50)          NULL,
    Activity   NVARCHAR(MAX)         NULL,
    ChangedBy  NVARCHAR(150)         NOT NULL,
    ActionType NVARCHAR(10)          NOT NULL
        CONSTRAINT CHK_ActionType
        CHECK (ActionType IN ('INSERT', 'UPDATE', 'DELETE', 'REJECTED')),
    ChangeDate DATETIME2  NOT NULL DEFAULT SYSDATETIME()
);
GO

-- PendingApproval table.
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


-- ################################################################
-- ## PART 1 -- AUTHENTICATION: TASK 1 (Login) & TASK 2 (Change Password)  (4_1_authentication)
-- ################################################################

USE SmartBankDB;
GO

-- TASK 1: Login system (sp_Login, sp_Logout). Confidentiality.
ALTER TABLE dbo.UserLogin
ADD PasswordLastChanged DATETIME2 NOT NULL DEFAULT SYSDATETIME();
GO

-- SecurityConfig: lockout/expiry policy values, avoids hardcoding. Confidentiality.
CREATE TABLE dbo.SecurityConfig (
    ConfigKey   NVARCHAR(50) NOT NULL PRIMARY KEY,
    ConfigValue INT          NOT NULL
);
GO

INSERT INTO dbo.SecurityConfig (ConfigKey, ConfigValue) VALUES
    ('MaxFailedAttempts', 3),      -- Component: Account lockout setting
    ('LockoutMinutes', 2),         -- Component: Account lockout setting
    ('PasswordExpiryDays', 90);    -- Component: Password expiration setting
GO

-- Audit identity helper is created before every authentication procedure that
-- references it. Keeping it here makes a clean top-to-bottom deployment valid.
CREATE OR ALTER FUNCTION dbo.fn_GetSessionUsername()
RETURNS NVARCHAR(150)
AS
BEGIN
    DECLARE @Username NVARCHAR(50), @Role NVARCHAR(50);
    DECLARE @StaffID INT = TRY_CAST(SESSION_CONTEXT(N'StaffID') AS INT);
    DECLARE @CustomerID INT = TRY_CAST(SESSION_CONTEXT(N'CustomerID') AS INT);

    IF @StaffID IS NOT NULL
        SELECT @Username = ul.Username, @Role = s.Position
        FROM dbo.UserLogin ul
        JOIN dbo.Staff s ON s.StaffID = ul.StaffID
        WHERE ul.StaffID = @StaffID;
    ELSE IF @CustomerID IS NOT NULL
        SELECT @Username = Username, @Role = 'Customer'
        FROM dbo.UserLogin
        WHERE CustomerID = @CustomerID;

    IF @Username IS NULL RETURN SUSER_NAME();
    RETURN CONCAT(@Username, ' (', @Role, ')');
END;
GO

-- Central password hashing objects retained as the documented C3 control.
-- The byte order matches the existing compiled format: salt + UTF-16 password.
CREATE OR ALTER FUNCTION dbo.fn_HashPassword
(
    @PlainPassword NVARCHAR(100),
    @Salt VARBINARY(32)
)
RETURNS VARBINARY(64)
AS
BEGIN
    RETURN HASHBYTES('SHA2_512', @Salt + CONVERT(VARBINARY(4000), @PlainPassword));
END;
GO

CREATE OR ALTER FUNCTION dbo.fn_VerifyPassword
(
    @Username NVARCHAR(50),
    @SuppliedPassword NVARCHAR(100)
)
RETURNS BIT
AS
BEGIN
    DECLARE @StoredHash VARBINARY(64), @StoredSalt VARBINARY(32);
    SELECT @StoredHash = PasswordHash, @StoredSalt = Salt
    FROM dbo.UserLogin
    WHERE Username = @Username AND IsActive = 1;

    RETURN CASE
        WHEN @StoredHash IS NOT NULL
         AND dbo.fn_HashPassword(@SuppliedPassword, @StoredSalt) = @StoredHash
        THEN 1 ELSE 0 END;
END;
GO

-- sp_Login: authenticates a user, sets SESSION_CONTEXT identity. Confidentiality.
CREATE OR ALTER PROCEDURE dbo.sp_Login
    @Username        NVARCHAR(50),
    @PlainPassword   NVARCHAR(100),
    @Success         BIT OUTPUT,          -- Component: Output parameters
    @PasswordExpired BIT OUTPUT,          -- Component: Output parameters
    @Message         NVARCHAR(200) OUTPUT -- Component: Output parameters
WITH EXECUTE AS OWNER
AS
BEGIN
    SET NOCOUNT ON;
    SET @Success = 0;
    SET @PasswordExpired = 0;

    DECLARE @LoginID INT, @StoredHash VARBINARY(64), @Salt VARBINARY(32),
            @StaffID INT, @CustomerID INT, @UserType NVARCHAR(10),
            @LockoutUntil DATETIME2, @IsActive BIT,
            @PasswordLastChanged DATETIME2,
            @MaxAttempts INT, @LockoutMinutes INT, @ExpiryDays INT,
            @RoleLabel NVARCHAR(50), @AttemptDescriptor NVARCHAR(150);

    -- Pull the current lockout/expiry rules from SecurityConfig
    SELECT @MaxAttempts    = ConfigValue FROM dbo.SecurityConfig WHERE ConfigKey = 'MaxFailedAttempts';
    SELECT @LockoutMinutes = ConfigValue FROM dbo.SecurityConfig WHERE ConfigKey = 'LockoutMinutes';
    SELECT @ExpiryDays     = ConfigValue FROM dbo.SecurityConfig WHERE ConfigKey = 'PasswordExpiryDays';

    -- Look up the account being logged into
    SELECT
        @LoginID = LoginID, @StoredHash = PasswordHash, @Salt = Salt,
        @StaffID = StaffID, @CustomerID = CustomerID, @UserType = UserType,
        @LockoutUntil = LockoutUntil, @IsActive = IsActive,
        @PasswordLastChanged = PasswordLastChanged
    FROM dbo.UserLogin
    WHERE Username = @Username;

-- Builds a 'claimed identity' string for REJECTED audit rows without touching ChangedBy (verified identity only). Confidentiality + Integrity.
    IF @LoginID IS NOT NULL
    BEGIN
        IF @UserType = 'Staff'
            SELECT @RoleLabel = Position FROM dbo.Staff WHERE StaffID = @StaffID;
        ELSE IF @UserType = 'Customer'
            SET @RoleLabel = 'Customer';

        SET @AttemptDescriptor = CONCAT('Attempted as: ', @Username, ', ', ISNULL(@RoleLabel, 'unknown role'));
    END
    ELSE
        SET @AttemptDescriptor = 'No account found for this username';

-- Unknown username and wrong password share one message so an attacker can't tell them apart. Confidentiality.
    IF @LoginID IS NULL
    BEGIN
        SET @Message = 'Invalid username or password.';
        INSERT INTO AuditSchema.AuditLog (TableName, ColumnName, RecordID, ChangedBy, ActionType, Activity)
        VALUES ('UserLogin', NULL, ISNULL(@Username, 'unknown'), dbo.fn_GetSessionUsername(), 'REJECTED', CONCAT(@Message, ' (', @AttemptDescriptor, ')'));
        RETURN;
    END

    IF @IsActive = 0
    BEGIN
        SET @Message = 'Invalid username or password.';
        INSERT INTO AuditSchema.AuditLog (TableName, ColumnName, RecordID, ChangedBy, ActionType, Activity)
        VALUES ('UserLogin', NULL, @Username, dbo.fn_GetSessionUsername(), 'REJECTED', CONCAT(@Message, ' (', @AttemptDescriptor, ')'));
        RETURN;
    END

-- Blocks login entirely while the account is locked out. Confidentiality.
    IF @LockoutUntil IS NOT NULL AND @LockoutUntil > SYSDATETIME()
    BEGIN
        SET @Message = 'Account temporarily locked. Please try again later.';
        INSERT INTO AuditSchema.AuditLog (TableName, ColumnName, RecordID, ChangedBy, ActionType, Activity)
        VALUES ('UserLogin', NULL, @Username, dbo.fn_GetSessionUsername(), 'REJECTED', CONCAT(@Message, ' (', @AttemptDescriptor, ')'));
        RETURN;
    END

-- Hashes + salts the typed password (SHA2_512) and compares to the stored hash -- never compares plaintext. Confidentiality.
    IF dbo.fn_VerifyPassword(@Username, @PlainPassword) = 1
    BEGIN
-- Correct-but-expired password blocks login and forces a change. Confidentiality.
        IF DATEDIFF(DAY, @PasswordLastChanged, SYSDATETIME()) > @ExpiryDays
        BEGIN
            SET @PasswordExpired = 1;
            SET @Success = 0;
            SET @Message = 'Password has expired. Please change your password to continue.';
            UPDATE dbo.UserLogin
            SET FailedLoginAttempts = 0, LockoutUntil = NULL
            WHERE LoginID = @LoginID;
            INSERT INTO AuditSchema.AuditLog (TableName, ColumnName, RecordID, ChangedBy, ActionType, Activity)
            VALUES ('UserLogin', NULL, @Username, dbo.fn_GetSessionUsername(), 'REJECTED', CONCAT(@Message, ' (', @AttemptDescriptor, ')'));
            RETURN;
        END

-- Sets SESSION_CONTEXT on success so every later RLS filter and proc check knows who's logged in. Confidentiality + Integrity.
        SET @Success = 1;
        SET @Message = 'Login successful.';
        UPDATE dbo.UserLogin
        SET FailedLoginAttempts = 0, LockoutUntil = NULL, LastLogin = SYSDATETIME()
        WHERE LoginID = @LoginID;

        EXEC sys.sp_set_session_context @key = N'UserType',   @value = @UserType;
        EXEC sys.sp_set_session_context @key = N'StaffID',    @value = @StaffID;
        EXEC sys.sp_set_session_context @key = N'CustomerID', @value = @CustomerID;
    END
    ELSE
    BEGIN
-- Wrong password increments the failed-attempt counter and locks the account once the threshold is hit. Confidentiality.
        UPDATE dbo.UserLogin
        SET FailedLoginAttempts = FailedLoginAttempts + 1,
            LockoutUntil = CASE WHEN FailedLoginAttempts + 1 >= @MaxAttempts
                                 THEN DATEADD(MINUTE, @LockoutMinutes, SYSDATETIME())
                                 ELSE LockoutUntil END
        WHERE LoginID = @LoginID;

        SET @Message = 'Invalid username or password.';
        INSERT INTO AuditSchema.AuditLog (TableName, ColumnName, RecordID, ChangedBy, ActionType, Activity)
        VALUES ('UserLogin', NULL, @Username, dbo.fn_GetSessionUsername(), 'REJECTED', CONCAT(@Message, ' (', @AttemptDescriptor, ')'));
    END
END;
GO

-- sp_Logout: clears SESSION_CONTEXT. Confidentiality.
CREATE OR ALTER PROCEDURE dbo.sp_Logout
WITH EXECUTE AS OWNER
AS
BEGIN
    SET NOCOUNT ON;
    EXEC sys.sp_set_session_context @key = N'UserType',   @value = NULL;
    EXEC sys.sp_set_session_context @key = N'StaffID',    @value = NULL;
    EXEC sys.sp_set_session_context @key = N'CustomerID', @value = NULL;
END;
GO


-- TASK 2: sp_ChangePassword. Rejects weak new passwords (8+ chars, mixed case, digit, symbol). Confidentiality.
CREATE OR ALTER FUNCTION dbo.fn_ValidatePasswordComplexity
    (@PlainPassword NVARCHAR(100))
RETURNS BIT
AS
BEGIN
    RETURN CASE
        WHEN LEN(@PlainPassword) >= 8
             AND @PlainPassword LIKE '%[0-9]%'
             AND @PlainPassword LIKE '%[a-z]%'
             AND @PlainPassword LIKE '%[A-Z]%'
             AND @PlainPassword LIKE '%[^a-zA-Z0-9]%'
        THEN 1 ELSE 0
    END;
END;
GO

-- Controlled password set/reset primitive retained for C3 documentation and
-- provisioning. It is intentionally not granted directly to a business role.
CREATE OR ALTER PROCEDURE dbo.sp_SetPassword
    @Username NVARCHAR(50),
    @NewPassword NVARCHAR(100)
WITH EXECUTE AS OWNER
AS
BEGIN
    SET NOCOUNT ON;

    IF dbo.fn_ValidatePasswordComplexity(@NewPassword) = 0
        THROW 51002, 'Password must be at least 8 characters and include uppercase, lowercase, digit, and special characters.', 1;

    DECLARE @NewSalt VARBINARY(32) = CRYPT_GEN_RANDOM(32);

    UPDATE dbo.UserLogin
    SET Salt = @NewSalt,
        PasswordHash = dbo.fn_HashPassword(@NewPassword, @NewSalt),
        PasswordLastChanged = SYSDATETIME(),
        FailedLoginAttempts = 0,
        LockoutUntil = NULL
    WHERE Username = @Username;

    IF @@ROWCOUNT = 0 THROW 51003, 'Username not found.', 1;
END;
GO

-- sp_ChangePassword stored procedure. Confidentiality.
CREATE OR ALTER PROCEDURE dbo.sp_ChangePassword
    @Username    NVARCHAR(50),
    @OldPassword NVARCHAR(100),
    @NewPassword NVARCHAR(100),
    @Success     BIT OUTPUT,           -- Component: Output parameters
    @Message     NVARCHAR(200) OUTPUT  -- Component: Output parameters
WITH EXECUTE AS OWNER
AS
BEGIN
    SET NOCOUNT ON;
    SET @Success = 0;

    DECLARE @LoginID INT, @StoredHash VARBINARY(64), @Salt VARBINARY(32),
            @IsActive BIT, @LockoutUntil DATETIME2,
            @StaffID INT, @UserType NVARCHAR(10),
            @MaxAttempts INT, @LockoutMinutes INT,
            @RoleLabel NVARCHAR(50), @AttemptDescriptor NVARCHAR(150);

    SELECT @MaxAttempts    = ConfigValue FROM dbo.SecurityConfig WHERE ConfigKey = 'MaxFailedAttempts';
    SELECT @LockoutMinutes = ConfigValue FROM dbo.SecurityConfig WHERE ConfigKey = 'LockoutMinutes';

-- Account lookup moved earlier so the audit descriptor is ready even when complexity fails first.
    SELECT @LoginID = LoginID, @StoredHash = PasswordHash, @Salt = Salt,
           @IsActive = IsActive, @LockoutUntil = LockoutUntil,
           @StaffID = StaffID, @UserType = UserType
    FROM dbo.UserLogin
    WHERE Username = @Username;

    -- Same "claimed identity" descriptor pattern as sp_Login -- see
    -- that procedure's comment for the full reasoning
    IF @LoginID IS NOT NULL
    BEGIN
        IF @UserType = 'Staff'
            SELECT @RoleLabel = Position FROM dbo.Staff WHERE StaffID = @StaffID;
        ELSE IF @UserType = 'Customer'
            SET @RoleLabel = 'Customer';

        SET @AttemptDescriptor = CONCAT('Attempted as: ', @Username, ', ', ISNULL(@RoleLabel, 'unknown role'));
    END
    ELSE
        SET @AttemptDescriptor = 'No account found for this username';

-- Checks new-password strength before touching the account at all. Confidentiality.
    IF dbo.fn_ValidatePasswordComplexity(@NewPassword) = 0
    BEGIN
        SET @Message = 'New password must be at least 8 characters and include an uppercase letter, a lowercase letter, a digit, and a special character.';
        INSERT INTO AuditSchema.AuditLog (TableName, ColumnName, RecordID, ChangedBy, ActionType, Activity)
        VALUES ('UserLogin', NULL, ISNULL(@Username, 'unknown'), dbo.fn_GetSessionUsername(), 'REJECTED', CONCAT(@Message, ' (', @AttemptDescriptor, ')'));
        RETURN;
    END

    -- Unknown or deactivated account -- generic message, same idea as Task #1
    IF @LoginID IS NULL OR @IsActive = 0
    BEGIN
        SET @Message = 'Current password is incorrect.';
        INSERT INTO AuditSchema.AuditLog (TableName, ColumnName, RecordID, ChangedBy, ActionType, Activity)
        VALUES ('UserLogin', NULL, ISNULL(@Username, 'unknown'), dbo.fn_GetSessionUsername(), 'REJECTED', CONCAT(@Message, ' (', @AttemptDescriptor, ')'));
        RETURN;
    END

-- Reuses the lockout mechanism for wrong old-password attempts. Confidentiality.
    IF @LockoutUntil IS NOT NULL AND @LockoutUntil > SYSDATETIME()
    BEGIN
        SET @Message = 'This account is temporarily locked. Please try again later.';
        INSERT INTO AuditSchema.AuditLog (TableName, ColumnName, RecordID, ChangedBy, ActionType, Activity)
        VALUES ('UserLogin', NULL, @Username, dbo.fn_GetSessionUsername(), 'REJECTED', CONCAT(@Message, ' (', @AttemptDescriptor, ')'));
        RETURN;
    END

-- Verifies the old password first. Confidentiality.
    IF dbo.fn_HashPassword(@OldPassword, @Salt) <> @StoredHash
    BEGIN
        -- Wrong old password -- counts as a failed attempt, same as Task #1
        UPDATE dbo.UserLogin
        SET FailedLoginAttempts = FailedLoginAttempts + 1,
            LockoutUntil = CASE WHEN FailedLoginAttempts + 1 >= @MaxAttempts
                                 THEN DATEADD(MINUTE, @LockoutMinutes, SYSDATETIME())
                                 ELSE LockoutUntil END
        WHERE LoginID = @LoginID;

        SET @Message = 'Current password is incorrect.';
        INSERT INTO AuditSchema.AuditLog (TableName, ColumnName, RecordID, ChangedBy, ActionType, Activity)
        VALUES ('UserLogin', NULL, @Username, dbo.fn_GetSessionUsername(), 'REJECTED', CONCAT(@Message, ' (', @AttemptDescriptor, ')'));
        RETURN;
    END

-- New salt + SHA2_512 hash, plus resets PasswordLastChanged and lockout state on success. Confidentiality.
    DECLARE @NewSalt VARBINARY(32) = CRYPT_GEN_RANDOM(32);

    UPDATE dbo.UserLogin
    SET PasswordHash         = dbo.fn_HashPassword(@NewPassword, @NewSalt),
        Salt                 = @NewSalt,
        PasswordLastChanged  = SYSDATETIME(),
        FailedLoginAttempts  = 0,
        LockoutUntil         = NULL
    WHERE LoginID = @LoginID;

    SET @Success = 1;
    SET @Message = 'Password changed successfully.';
END;
GO


-- ================================================================
-- ## PART 2 -- AUTHORIZATION / RBAC: TASK 3  (4_2_authorization_rbac)
-- ################################################################

USE SmartBankDB;
GO

-- TASK 3: creates the 4 roles the assignment names -- DBA, Bank_Manager, Bank_Officer, Customer. Integrity.
CREATE ROLE DBA;
GO
CREATE ROLE Bank_Manager;
GO
CREATE ROLE Bank_Officer;
GO
CREATE ROLE Customer;
GO


-- Individual native logins per test identity -- role-descriptive names visible directly
-- in the SSMS SQL Server Authentication dropdown. Each connects via SQL Auth and is
-- recognised by the logon trigger below (populates SESSION_CONTEXT automatically).
-- Kept alongside the 4 role logins above -- role logins hold the permissions, these hold identity.
IF NOT EXISTS (SELECT 1 FROM sys.sql_logins WHERE name = 'SmartBank_Manager1')
    CREATE LOGIN SmartBank_Manager1   WITH PASSWORD = 'Manager1P@ss!',  CHECK_POLICY = OFF;
GO
IF NOT EXISTS (SELECT 1 FROM sys.sql_logins WHERE name = 'SmartBank_Manager2')
    CREATE LOGIN SmartBank_Manager2   WITH PASSWORD = 'Manager2P@ss!',  CHECK_POLICY = OFF;
GO
IF NOT EXISTS (SELECT 1 FROM sys.sql_logins WHERE name = 'SmartBank_DBA1')
    CREATE LOGIN SmartBank_DBA1       WITH PASSWORD = 'Dba1P@ss!',      CHECK_POLICY = OFF;
GO
IF NOT EXISTS (SELECT 1 FROM sys.sql_logins WHERE name = 'SmartBank_DBA2')
    CREATE LOGIN SmartBank_DBA2       WITH PASSWORD = 'Dba2P@ss!',      CHECK_POLICY = OFF;
GO
IF NOT EXISTS (SELECT 1 FROM sys.sql_logins WHERE name = 'SmartBank_Officer1')
    CREATE LOGIN SmartBank_Officer1   WITH PASSWORD = 'Officer1P@ss!',  CHECK_POLICY = OFF;
GO
IF NOT EXISTS (SELECT 1 FROM sys.sql_logins WHERE name = 'SmartBank_Officer2')
    CREATE LOGIN SmartBank_Officer2   WITH PASSWORD = 'Officer2P@ss!',  CHECK_POLICY = OFF;
GO
IF NOT EXISTS (SELECT 1 FROM sys.sql_logins WHERE name = 'SmartBank_Customer1')
    CREATE LOGIN SmartBank_Customer1  WITH PASSWORD = 'Customer1P@ss!', CHECK_POLICY = OFF;
GO
IF NOT EXISTS (SELECT 1 FROM sys.sql_logins WHERE name = 'SmartBank_Customer2')
    CREATE LOGIN SmartBank_Customer2  WITH PASSWORD = 'Customer2P@ss!', CHECK_POLICY = OFF;
GO

USE SmartBankDB;
GO

-- Map each individual login into SmartBankDB and put them in the correct role -- role membership
-- is what grants the actual permissions (via the existing GRANT/DENY on the 4 role logins above).
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name='SmartBank_Manager1')
    CREATE USER SmartBank_Manager1   FOR LOGIN SmartBank_Manager1;
GO
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name='SmartBank_Manager2')
    CREATE USER SmartBank_Manager2   FOR LOGIN SmartBank_Manager2;
GO
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name='SmartBank_DBA1')
    CREATE USER SmartBank_DBA1       FOR LOGIN SmartBank_DBA1;
GO
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name='SmartBank_DBA2')
    CREATE USER SmartBank_DBA2       FOR LOGIN SmartBank_DBA2;
GO
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name='SmartBank_Officer1')
    CREATE USER SmartBank_Officer1   FOR LOGIN SmartBank_Officer1;
GO
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name='SmartBank_Officer2')
    CREATE USER SmartBank_Officer2   FOR LOGIN SmartBank_Officer2;
GO
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name='SmartBank_Customer1')
    CREATE USER SmartBank_Customer1  FOR LOGIN SmartBank_Customer1;
GO
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name='SmartBank_Customer2')
    CREATE USER SmartBank_Customer2  FOR LOGIN SmartBank_Customer2;
GO

-- Guarded so re-running the codebase doesn't throw "already a member" errors.
IF IS_ROLEMEMBER('Bank_Manager', 'SmartBank_Manager1') = 0
    ALTER ROLE Bank_Manager  ADD MEMBER SmartBank_Manager1;
IF IS_ROLEMEMBER('Bank_Manager', 'SmartBank_Manager2') = 0
    ALTER ROLE Bank_Manager  ADD MEMBER SmartBank_Manager2;
IF IS_ROLEMEMBER('DBA', 'SmartBank_DBA1') = 0
    ALTER ROLE DBA           ADD MEMBER SmartBank_DBA1;
IF IS_ROLEMEMBER('DBA', 'SmartBank_DBA2') = 0
    ALTER ROLE DBA           ADD MEMBER SmartBank_DBA2;
IF IS_ROLEMEMBER('Bank_Officer', 'SmartBank_Officer1') = 0
    ALTER ROLE Bank_Officer  ADD MEMBER SmartBank_Officer1;
IF IS_ROLEMEMBER('Bank_Officer', 'SmartBank_Officer2') = 0
    ALTER ROLE Bank_Officer  ADD MEMBER SmartBank_Officer2;
IF IS_ROLEMEMBER('Customer', 'SmartBank_Customer1') = 0
    ALTER ROLE Customer      ADD MEMBER SmartBank_Customer1;
IF IS_ROLEMEMBER('Customer', 'SmartBank_Customer2') = 0
    ALTER ROLE Customer      ADD MEMBER SmartBank_Customer2;
GO

-- RecoveryAdmin: 5th role for recovery/history access, DBA nested as a member -- keeps DBA's direct grants matching the rubric literally ('own record', 'not data'). Confidentiality + Integrity + Availability.
CREATE ROLE RecoveryAdmin;
GO
ALTER ROLE RecoveryAdmin ADD MEMBER DBA;
GO


-- Denies direct SELECT/INSERT/UPDATE/DELETE on all base tables to all 4 roles -- provable least-privilege. Confidentiality + Integrity.
DENY SELECT, INSERT, UPDATE, DELETE ON dbo.Staff             TO DBA, Bank_Manager, Bank_Officer, Customer;
DENY SELECT, INSERT, UPDATE, DELETE ON dbo.Customer          TO DBA, Bank_Manager, Bank_Officer, Customer;
DENY SELECT, INSERT, UPDATE, DELETE ON dbo.Account           TO DBA, Bank_Manager, Bank_Officer, Customer;
DENY SELECT, INSERT, UPDATE, DELETE ON dbo.TransactionRecord TO DBA, Bank_Manager, Bank_Officer, Customer;
DENY SELECT, INSERT, UPDATE, DELETE ON dbo.PendingApproval   TO DBA, Bank_Manager, Bank_Officer, Customer;
-- Same DENY extended to UserLogin/SecurityConfig -- the most sensitive tables weren't in the original list. Confidentiality.
DENY SELECT, INSERT, UPDATE, DELETE ON dbo.UserLogin         TO DBA, Bank_Manager, Bank_Officer, Customer;
DENY SELECT, INSERT, UPDATE, DELETE ON dbo.SecurityConfig    TO DBA, Bank_Manager, Bank_Officer, Customer;
GO


-- Grants DBA CREATE TABLE + ALTER ON SCHEMA::dbo (not db_ddladmin, which would also reach AuditSchema). Integrity.
GRANT CREATE TABLE TO DBA;
GRANT ALTER ON SCHEMA::dbo TO DBA;
GO

-- trg_PreventVersioningDisable: blocks SYSTEM_VERSIONING=OFF and DROP COLUMN on the 4 core tables so the audit/recovery trail can't be silently disabled. Integrity + Availability.
CREATE OR ALTER TRIGGER trg_PreventVersioningDisable
ON DATABASE
FOR ALTER_TABLE
AS
BEGIN
    DECLARE @EventData XML = EVENTDATA();
    DECLARE @TableName NVARCHAR(128) = @EventData.value('(/EVENT_INSTANCE/ObjectName)[1]', 'NVARCHAR(128)');
    DECLARE @CommandText NVARCHAR(MAX) = @EventData.value('(/EVENT_INSTANCE/TSQLCommand/CommandText)[1]', 'NVARCHAR(MAX)');

    IF @TableName IN ('Staff', 'Customer', 'Account', 'TransactionRecord')
    BEGIN
        IF @CommandText LIKE '%SYSTEM_VERSIONING%OFF%'
        BEGIN
            RAISERROR('Disabling temporal versioning on this table is not permitted -- it protects the audit trail and Availability''s recoverability guarantee. If this is genuinely necessary, a sysadmin must first run DISABLE TRIGGER trg_PreventVersioningDisable ON DATABASE.', 16, 1);
            ROLLBACK;
        END
        ELSE IF @CommandText LIKE '%DROP COLUMN%'
        BEGIN
            RAISERROR('Dropping a column from this table is not permitted -- it would also permanently erase that column''s entire history, even with versioning still ON. If this is genuinely necessary, a sysadmin must first run DISABLE TRIGGER trg_PreventVersioningDisable ON DATABASE.', 16, 1);
            ROLLBACK;
        END
    END
END;
GO

ENABLE TRIGGER trg_PreventVersioningDisable ON DATABASE;
GO


-- Confirms DBA's schema rights never imply data rights (already enforced by the DENY block above). Integrity.


-- ================================================================
-- ## PART 3 -- VIEWS: TASK 4  (4_3_views)
-- ################################################################

-- TASK 4: 14 views so every role queries a purpose-built view, never a base table. Confidentiality.


-- vw_StaffDirectory: name + phone only, visible to all 4 roles -- but only after a successful
-- sp_Login, not just SQL-role membership. UserType is set by sp_Login on every successful login
-- (Staff or Customer alike), so its absence means this session never actually authenticated. Confidentiality.
CREATE OR ALTER VIEW dbo.vw_StaffDirectory AS
    SELECT StaffName, Phone
    FROM dbo.Staff
    WHERE IsActive = 1
      AND SESSION_CONTEXT(N'UserType') IS NOT NULL;
GO
GRANT SELECT ON dbo.vw_StaffDirectory TO DBA, Bank_Manager, Bank_Officer, Customer;
GO

-- vw_StaffOwnRecord: full staff row; filtered to 'own row only' by Task 5's RLS. Confidentiality.
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

-- Salary remains hidden from unrelated roles, while each staff role can see
-- it only through its already row/role-restricted staff view.
GRANT UNMASK ON OBJECT::dbo.Staff (Salary) TO DBA;
GRANT UNMASK ON OBJECT::dbo.Staff (Salary) TO Bank_Manager;
GRANT UNMASK ON OBJECT::dbo.Staff (Salary) TO Bank_Officer;
GO


-- vw_CustomerAll: full customer row, for Manager/Officer. Confidentiality.
CREATE OR ALTER VIEW dbo.vw_CustomerAll AS
    -- Managers and officers need customer account operations, not unrestricted identity exposure.
    SELECT CustomerID, CustomerName, Phone, Address, IsActive
    FROM dbo.Customer;
GO
GRANT SELECT ON dbo.vw_CustomerAll TO Bank_Manager, Bank_Officer;
GO

-- Customer own profile view: RLS ensures a customer can only access their own information.
CREATE OR ALTER VIEW dbo.vw_CustomerOwnProfile AS
    SELECT CustomerID, CustomerName, Phone, Address, IsActive
    FROM dbo.Customer
    WHERE CustomerID = CAST(SESSION_CONTEXT(N'CustomerID') AS INT);
GO
GRANT SELECT ON dbo.vw_CustomerOwnProfile TO Customer;
GO

-- UNMASK on own record only: RLS above already limits Customer to CustomerID = their own row,
-- so this only reveals the masked Phone/Address within that one row -- not other customers'. Confidentiality.
GRANT UNMASK ON OBJECT::dbo.Customer (Phone) TO Bank_Manager;
GRANT UNMASK ON OBJECT::dbo.Customer (Address) TO Bank_Manager;
GRANT UNMASK ON OBJECT::dbo.Customer (Phone) TO Bank_Officer;
GRANT UNMASK ON OBJECT::dbo.Customer (Address) TO Bank_Officer;
GRANT UNMASK ON OBJECT::dbo.Customer (Phone) TO Customer;
GRANT UNMASK ON OBJECT::dbo.Customer (Address) TO Customer;
GO

-- Component: vw_AccountAll
CREATE OR ALTER VIEW dbo.vw_AccountAll AS
    SELECT AccountID, CustomerID, AccountType, Balance, IsActive
    FROM dbo.Account;
GO
GRANT SELECT ON dbo.vw_AccountAll TO Bank_Manager, Bank_Officer;
GO

-- C1 least-privilege UNMASK policy. Manager sees true balances in the all-
-- account view; a Customer sees true balances only through vw_AccountOwn.
-- Bank_Officer intentionally receives no UNMASK grant and sees 0.00 instead.
GRANT UNMASK ON OBJECT::dbo.Account (Balance) TO Bank_Manager;
GRANT UNMASK ON OBJECT::dbo.Account (Balance) TO Bank_Officer;
GRANT UNMASK ON OBJECT::dbo.Account (Balance) TO Customer;
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


-- vw_TransactionAll: all transactions, for Manager/Officer. Confidentiality.
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


-- vw_PendingApprovalAll: all pending approval requests, for Manager. Confidentiality.
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


-- Audit contents may contain sensitive before/after values, so only DBA can
-- inspect the custom audit trail. This restores C6's documented access rule.
GRANT SELECT ON AuditSchema.AuditLog TO DBA;
GO

-- Component: vw_Staff_History
-- (Column names corrected to match A's actual hidden period
-- columns: SysStartTime, SysEndTime -- not ValidFrom/ValidTo)
CREATE OR ALTER VIEW dbo.vw_Staff_History AS
    SELECT StaffID, StaffName, Position, Branch, Phone, Salary,
           SysStartTime, SysEndTime
    FROM dbo.Staff FOR SYSTEM_TIME ALL;
GO
GRANT SELECT ON dbo.vw_Staff_History TO RecoveryAdmin;
GO

-- Component: vw_Customer_History
CREATE OR ALTER VIEW dbo.vw_Customer_History AS
    SELECT CustomerID, CustomerName, ICNumber, Phone, Address,
           SysStartTime, SysEndTime
    FROM dbo.Customer FOR SYSTEM_TIME ALL;
GO
GRANT SELECT ON dbo.vw_Customer_History TO RecoveryAdmin;
GO

-- Component: vw_Account_History
CREATE OR ALTER VIEW dbo.vw_Account_History AS
    SELECT AccountID, CustomerID, AccountType, Balance,
           SysStartTime, SysEndTime
    FROM dbo.Account FOR SYSTEM_TIME ALL;
GO
GRANT SELECT ON dbo.vw_Account_History TO RecoveryAdmin;
GO

-- Component: vw_TransactionRecord_History
CREATE OR ALTER VIEW dbo.vw_TransactionRecord_History AS
    SELECT TransID, AccountID, ToAccountID, TransDate, Amount,
           TransactionType, SysStartTime, SysEndTime
    FROM dbo.TransactionRecord FOR SYSTEM_TIME ALL;
GO
GRANT SELECT ON dbo.vw_TransactionRecord_History TO RecoveryAdmin;
GO


-- ================================================================
-- ## PART 4 -- ROW-LEVEL SECURITY: TASK 5  (4_4_row_level_security)
-- ################################################################

USE SmartBankDB;
GO

-- TASK 5: adds RLS filtering to the 4 'Own' views, plus grants sp_Login/Logout/ChangePassword to PUBLIC (needed before anyone has a role). Confidentiality.
GRANT EXECUTE ON dbo.sp_Login          TO PUBLIC;
GRANT EXECUTE ON dbo.sp_Logout         TO PUBLIC;
GRANT EXECUTE ON dbo.sp_ChangePassword TO PUBLIC;
GO


-- vw_StaffOwnRecord filtered to the caller's own StaffID via SESSION_CONTEXT. Confidentiality.
CREATE OR ALTER VIEW dbo.vw_StaffOwnRecord AS
    SELECT StaffID, StaffName, Position, Branch, Phone, Salary, IsActive
    FROM dbo.Staff
    WHERE StaffID = CAST(SESSION_CONTEXT(N'StaffID') AS INT);
GO


-- vw_AccountOwn filtered to the caller's own CustomerID via SESSION_CONTEXT. Confidentiality.
CREATE OR ALTER VIEW dbo.vw_AccountOwn AS
    SELECT AccountID, CustomerID, AccountType, Balance, IsActive
    FROM dbo.Account
    WHERE CustomerID = CAST(SESSION_CONTEXT(N'CustomerID') AS INT);
GO


-- ALTER vw_TransactionOwn to add the RLS filter. Confidentiality.
CREATE OR ALTER VIEW dbo.vw_TransactionOwn AS
    SELECT
        t.TransID, t.AccountID, t.ToAccountID, t.TransDate,
        t.Amount, t.TransactionType, a.CustomerID
    FROM dbo.TransactionRecord t
    JOIN dbo.Account a ON t.AccountID = a.AccountID
    WHERE a.CustomerID = CAST(SESSION_CONTEXT(N'CustomerID') AS INT);
GO


-- ALTER vw_PendingApprovalOwn to add the RLS filter. Confidentiality.
CREATE OR ALTER VIEW dbo.vw_PendingApprovalOwn AS
    SELECT
        p.RequestID, p.AccountID, p.RequestedBy, p.ApprovedBy, p.Amount,
        p.TransactionType, p.ToAccountID, p.Status, p.RequestDate,
        p.ApprovalDate, a.CustomerID
    FROM dbo.PendingApproval p
    JOIN dbo.Account a ON p.AccountID = a.AccountID
    WHERE a.CustomerID = CAST(SESSION_CONTEXT(N'CustomerID') AS INT);
GO


-- PART 5: native SQL Server Audit -- logins, schema changes, permission changes, sensitive reads. Confidentiality + Integrity. Run this section as a sysadmin login -- CREATE SERVER AUDIT and its specifications require server-level rights no application role has.

USE master;
GO

-- [C6.1] Creates the server audit object everything below writes into. Confidentiality + Integrity.
IF NOT EXISTS (SELECT 1 FROM sys.server_audits WHERE name = 'SmartBank_ServerAudit')
    CREATE SERVER AUDIT SmartBank_ServerAudit
    TO FILE
    (
        FILEPATH = 'C:\SQLAudit\',
        MAXSIZE = 100 MB,
        MAX_ROLLOVER_FILES = 50,
        RESERVE_DISK_SPACE = OFF
    )
    WITH (ON_FAILURE = CONTINUE);
GO

-- The server audit must be OFF before you can change its file target
ALTER SERVER AUDIT SmartBank_ServerAudit WITH (STATE = OFF);
GO

ALTER SERVER AUDIT SmartBank_ServerAudit
TO FILE
(
    FILEPATH = 'C:\SQLAudit\',
    MAXSIZE = 100 MB,
    MAX_ROLLOVER_FILES = 50,
    RESERVE_DISK_SPACE = OFF
);
GO

-- Confirm it's now pointing at the right place
SELECT name, status_desc
FROM sys.dm_server_audit_status;

-- [C6.2] Audits successful/failed logins and logouts. Confidentiality.
-- Server audit is intentionally left OFF here -- you can't drop or
-- recreate a specification while its parent audit is enabled.
-- [C6.6] turns everything on together, once setup is complete.
IF EXISTS (SELECT 1 FROM sys.server_audit_specifications WHERE name = 'SmartBank_LoginAuditSpec')
BEGIN
    ALTER SERVER AUDIT SPECIFICATION SmartBank_LoginAuditSpec WITH (STATE = OFF);
    DROP SERVER AUDIT SPECIFICATION SmartBank_LoginAuditSpec;
END
GO

CREATE SERVER AUDIT SPECIFICATION SmartBank_LoginAuditSpec
FOR SERVER AUDIT SmartBank_ServerAudit
    ADD (SUCCESSFUL_LOGIN_GROUP),
    ADD (FAILED_LOGIN_GROUP),
    ADD (LOGOUT_GROUP)
WITH (STATE = OFF);  -- switched ON in [C6.6]
GO


USE SmartBankDB;
GO

-- [C6.3-5] Audits schema changes, permission changes, and sensitive SELECT on Customer/Account/UserLogin. Confidentiality + Integrity.
IF EXISTS (SELECT 1 FROM sys.database_audit_specifications WHERE name = 'SmartBank_DatabaseAuditSpec')
BEGIN
    ALTER DATABASE AUDIT SPECIFICATION SmartBank_DatabaseAuditSpec WITH (STATE = OFF);
    DROP DATABASE AUDIT SPECIFICATION SmartBank_DatabaseAuditSpec;
END
GO

CREATE DATABASE AUDIT SPECIFICATION SmartBank_DatabaseAuditSpec
FOR SERVER AUDIT SmartBank_ServerAudit
    -- [C6.3] schema changes
    ADD (SCHEMA_OBJECT_CHANGE_GROUP),
    ADD (DATABASE_OBJECT_CHANGE_GROUP),
    -- [C6.4] permission changes
    ADD (DATABASE_PERMISSION_CHANGE_GROUP),
    ADD (SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP),
    -- [C6.5] sensitive read access
    ADD (SELECT ON OBJECT::dbo.Customer  BY public),
    ADD (SELECT ON OBJECT::dbo.Account   BY public),
    ADD (SELECT ON OBJECT::dbo.UserLogin BY public)
WITH (STATE = OFF);
GO


-- [C6.6] Turns the audit and all specifications ON.
USE master;
GO
ALTER SERVER AUDIT SmartBank_ServerAudit WITH (STATE = ON);
GO
ALTER SERVER AUDIT SPECIFICATION SmartBank_LoginAuditSpec WITH (STATE = ON);
GO

USE SmartBankDB;
GO
ALTER DATABASE AUDIT SPECIFICATION SmartBank_DatabaseAuditSpec WITH (STATE = ON);
GO


-- [C6.7] sp_DBA_ViewAuditFile: DBA-only wrapper for reading raw audit records, so nobody needs direct CONTROL SERVER. Confidentiality + Integrity.
CREATE OR ALTER PROCEDURE dbo.sp_DBA_ViewAuditFile
AS
BEGIN
    SET NOCOUNT ON;

    -- Application-level gate: only members of the DBA role may run this at all
    IF IS_MEMBER('DBA') = 0
    BEGIN
        THROW 51000, 'Access denied: audit records are restricted to the DBA role.', 1;
        RETURN;
    END

    SELECT
        event_time,
        action_id,
        succeeded,
        server_principal_name,
        database_name,
        object_name,
        statement
    FROM sys.fn_get_audit_file('C:\SQLAudit\*.sqlaudit', DEFAULT, DEFAULT)
    ORDER BY event_time DESC;
END;
GO

-- Never granted to public -- DENY always overrides GRANT, so simply not granting EXECUTE is sufficient.
GRANT EXECUTE ON dbo.sp_DBA_ViewAuditFile TO DBA;
GO

-- C7: focused login/logout audit reader with every field required by the
-- documented audit matrix: login, client host, event, outcome, and timestamp.
CREATE OR ALTER PROCEDURE dbo.sp_DBA_ViewLoginAudit
AS
BEGIN
    SET NOCOUNT ON;

    IF IS_MEMBER('DBA') = 0
        THROW 51004, 'Access denied: login audit records are restricted to the DBA role.', 1;

    SELECT
        event_time,
        server_principal_name AS LoginName,
        client_ip AS ClientHost,
        CASE action_id
            WHEN 'LGIS' THEN 'Login Succeeded'
            WHEN 'LGIF' THEN 'Login Failed'
            WHEN 'LGO'  THEN 'Logout'
            ELSE action_id
        END AS EventType,
        succeeded AS Succeeded
    FROM sys.fn_get_audit_file('C:\SQLAudit\*.sqlaudit', DEFAULT, DEFAULT)
    WHERE action_id IN ('LGIS', 'LGIF', 'LGO')
    ORDER BY event_time DESC;
END;
GO

GRANT EXECUTE ON dbo.sp_DBA_ViewLoginAudit TO DBA;
GO

-- SQL Server 2022 supports this narrower server permission for reading audit
-- files; it avoids the original script's excessive CONTROL SERVER grant.
USE master;
GO
GRANT VIEW SERVER SECURITY AUDIT TO SmartBank_DBA1;
GRANT VIEW SERVER SECURITY AUDIT TO SmartBank_DBA2;
GO
USE SmartBankDB;
GO


-- Additional real DBA logins need VIEW SERVER SECURITY AUDIT during onboarding.
PRINT 'Reminder: grant VIEW SERVER SECURITY AUDIT to each approved real DBA login.';
GO

PRINT 'C6 - SQL Server Audit setup complete. Server audit and all 4 specifications are ON.';

-- PART 6: TDE (whole-database encryption) + CLE (Customer.ICNumber column encryption). Confidentiality. Passwords below are placeholders for this assignment -- a real deployment would generate these securely and store them outside the script entirely.

USE SmartBankDB;
GO

-- [C2.1] Database Master Key -- root of this database's own encryption hierarchy. Confidentiality.
IF NOT EXISTS (SELECT 1 FROM sys.symmetric_keys WHERE name = '##MS_DatabaseMasterKey##')
    CREATE MASTER KEY ENCRYPTION BY PASSWORD = 'SmartBank_DMK_P@ss2026!';
GO
-- [C2.2] Certificate protecting the CLE symmetric key. Confidentiality.
IF NOT EXISTS (SELECT 1 FROM sys.certificates WHERE name = 'CLE_ICNumber_Cert')
    CREATE CERTIFICATE CLE_ICNumber_Cert
        WITH SUBJECT = 'Column-level encryption certificate for Customer.ICNumber';
GO
-- [C2.3] AES_256 symmetric key that actually encrypts/decrypts ICNumber. Confidentiality.
IF NOT EXISTS (SELECT 1 FROM sys.symmetric_keys WHERE name = 'CLE_ICNumber_SymKey')
    CREATE SYMMETRIC KEY CLE_ICNumber_SymKey
        WITH ALGORITHM = AES_256
        ENCRYPTION BY CERTIFICATE CLE_ICNumber_Cert;
GO

-- [C2.4] Re-encrypts ICNumber from the seed data's placeholder passphrase to the real CLE key. Confidentiality.

OPEN SYMMETRIC KEY CLE_ICNumber_SymKey
    DECRYPTION BY CERTIFICATE CLE_ICNumber_Cert;
 
UPDATE dbo.Customer
SET ICNumber = EncryptByKey(
    Key_GUID('CLE_ICNumber_SymKey'),
    CONVERT(VARBINARY(MAX), CONVERT(NVARCHAR(20), DecryptByPassphrase('TEMP_PLACEHOLDER_KEY', ICNumber)))
);
 
CLOSE SYMMETRIC KEY CLE_ICNumber_SymKey;
GO
 
PRINT 'C2.4 - ICNumber data migrated from placeholder to real CLE encryption.';
GO

-- [C2.5] sp_DecryptICNumber: lets Manager/Officer decrypt a customer's IC number, with no direct key access granted to them. Confidentiality.

CREATE OR ALTER PROCEDURE dbo.sp_DecryptICNumber
    @CustomerID INT
WITH EXECUTE AS OWNER
AS
BEGIN
    SET NOCOUNT ON;
 
    OPEN SYMMETRIC KEY CLE_ICNumber_SymKey
        DECRYPTION BY CERTIFICATE CLE_ICNumber_Cert;
 
    SELECT
        CustomerID,
        CustomerName,
        CONVERT(NVARCHAR(20), DecryptByKey(ICNumber)) AS ICNumber_Decrypted
    FROM dbo.Customer
    WHERE CustomerID = @CustomerID;
 
    CLOSE SYMMETRIC KEY CLE_ICNumber_SymKey;
END;
GO
 
GRANT EXECUTE ON dbo.sp_DecryptICNumber TO Bank_Manager;
GO
GRANT EXECUTE ON dbo.sp_DecryptICNumber TO Bank_Officer;
GO


-- sp_DecryptOwnICNumber: lets a Customer decrypt ONLY their own IC number -- nothing else on their row. Confidentiality.
CREATE OR ALTER PROCEDURE dbo.sp_DecryptOwnICNumber
WITH EXECUTE AS OWNER
AS
BEGIN
    SET NOCOUNT ON;
    DECLARE @CallerCustomerID INT = TRY_CAST(SESSION_CONTEXT(N'CustomerID') AS INT);

    IF @CallerCustomerID IS NULL
    BEGIN
        THROW 51000, 'You must be logged in as a customer to use this.', 1;
        RETURN;
    END

    OPEN SYMMETRIC KEY CLE_ICNumber_SymKey
        DECRYPTION BY CERTIFICATE CLE_ICNumber_Cert;

    SELECT
        CustomerID,
        CONVERT(NVARCHAR(20), DecryptByKey(ICNumber)) AS ICNumber_Decrypted
    FROM dbo.Customer
    WHERE CustomerID = @CallerCustomerID;

    CLOSE SYMMETRIC KEY CLE_ICNumber_SymKey;
END;
GO

GRANT EXECUTE ON dbo.sp_DecryptOwnICNumber TO Customer;
GO


-- ================================================================
-- [C2.6] Master-level DMK for TDE's certificate (must live in master). Confidentiality.
USE master;
GO

IF NOT EXISTS (SELECT 1 FROM sys.symmetric_keys WHERE name = '##MS_DatabaseMasterKey##')
    CREATE MASTER KEY ENCRYPTION BY PASSWORD = 'SmartBank_MasterDMK_P@ss2026!';
GO

-- [C2.7] TDE certificate (server-level, stored in master). Confidentiality.
IF NOT EXISTS (SELECT 1 FROM sys.certificates WHERE name = 'TDE_SmartBankDB_Cert')
    CREATE CERTIFICATE TDE_SmartBankDB_Cert
        WITH SUBJECT = 'TDE certificate for SmartBankDB';
GO

-- [C2.8] Database Encryption Key TDE uses to encrypt the actual database file. Confidentiality.
USE SmartBankDB;
GO

IF NOT EXISTS (SELECT 1 FROM sys.dm_database_encryption_keys WHERE database_id = DB_ID('SmartBankDB'))
BEGIN
    CREATE DATABASE ENCRYPTION KEY
        WITH ALGORITHM = AES_256
        ENCRYPTION BY SERVER CERTIFICATE TDE_SmartBankDB_Cert;
END
GO

-- [C2.9] Turns on whole-database file encryption. Confidentiality.
USE master;
GO

ALTER DATABASE SmartBankDB SET ENCRYPTION ON;
GO

-- Check progress/status (encryption_state 3 = Encrypted, complete)
SELECT
    db.name AS database_name,
    dek.encryption_state,
    dek.percent_complete
FROM sys.dm_database_encryption_keys dek
JOIN sys.databases db ON dek.database_id = db.database_id
WHERE db.name = 'SmartBankDB';
GO

-- [C2.10] Backs up SmartBankDB's Database Master Key. Confidentiality.
USE SmartBankDB;
GO

BACKUP MASTER KEY TO FILE = 'C:\SQLKeys\SmartBankDB_DMK.key'
    ENCRYPTION BY PASSWORD = 'SmartBank_KeyBackup_P@ss2026!';
GO

-- [C2.11] Backs up the CLE certificate + private key -- losing it makes ICNumber permanently undecryptable. Confidentiality.
BACKUP CERTIFICATE CLE_ICNumber_Cert
    TO FILE = 'C:\SQLKeys\CLE_ICNumber_Cert.cer'
    WITH PRIVATE KEY (
        FILE = 'C:\SQLKeys\CLE_ICNumber_Cert.pvk',
        ENCRYPTION BY PASSWORD = 'SmartBank_KeyBackup_P@ss2026!'
    );
GO

-- [C2.12] Backs up the TDE certificate + private key (from master). Confidentiality.
USE master;
GO

BACKUP CERTIFICATE TDE_SmartBankDB_Cert
    TO FILE = 'C:\SQLKeys\TDE_SmartBankDB_Cert.cer'
    WITH PRIVATE KEY (
        FILE = 'C:\SQLKeys\TDE_SmartBankDB_Cert.pvk',
        ENCRYPTION BY PASSWORD = 'SmartBank_KeyBackup_P@ss2026!'
    );
GO

USE SmartBankDB;
GO

PRINT 'C2 - TDE and CLE setup complete. All keys and certificates backed up.';

-- ================================================================
-- PART 6B: C4 STATIC MASKING + C5 ANONYMISATION
-- These are sanitized staging copies for safe export to development and
-- analytics environments. They remain in dedicated schemas so the compiled
-- script does not weaken cross-database security or grant DBA direct access to
-- production business tables.
-- ================================================================

USE SmartBankDB;
GO

CREATE SCHEMA Sanitized AUTHORIZATION dbo;
GO

CREATE TABLE Sanitized.Customer_Sanitized (
    CustomerID INT NOT NULL PRIMARY KEY,
    CustomerName NVARCHAR(100) NOT NULL,
    ICNumber VARBINARY(MAX) NULL,
    ICNumberHash VARBINARY(32) NULL,
    Phone NVARCHAR(20) NOT NULL,
    Address NVARCHAR(255) NOT NULL,
    IsActive BIT NOT NULL
);
GO

CREATE TABLE Sanitized.Staff_Sanitized (
    StaffID INT NOT NULL PRIMARY KEY,
    StaffName NVARCHAR(100) NOT NULL,
    Position NVARCHAR(50) NOT NULL,
    Branch NVARCHAR(100) NOT NULL,
    Phone NVARCHAR(20) NOT NULL,
    Salary DECIMAL(15,2) NOT NULL,
    IsActive BIT NOT NULL
);
GO

-- C4: irreversibly replaces direct identifiers with unrelated synthetic data.
-- EXECUTE AS OWNER lets the module read source rows without giving DBA direct
-- SELECT permission on production tables.
CREATE OR ALTER PROCEDURE dbo.sp_RefreshDevData
WITH EXECUTE AS OWNER
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    BEGIN TRY
        BEGIN TRANSACTION;

        TRUNCATE TABLE Sanitized.Customer_Sanitized;
        INSERT INTO Sanitized.Customer_Sanitized
            (CustomerID, CustomerName, ICNumber, ICNumberHash, Phone, Address, IsActive)
        SELECT
            CustomerID,
            CONCAT('Test Customer ', CustomerID, ' ', LEFT(CONVERT(VARCHAR(36), NEWID()), 8)),
            NULL,
            NULL,
            CONCAT('01', RIGHT('00000000' + CONVERT(VARCHAR(8), ABS(CHECKSUM(NEWID())) % 100000000), 8)),
            CONCAT('Synthetic Address ', CustomerID, ', Kuala Lumpur'),
            IsActive
        FROM dbo.Customer;

        TRUNCATE TABLE Sanitized.Staff_Sanitized;
        INSERT INTO Sanitized.Staff_Sanitized
            (StaffID, StaffName, Position, Branch, Phone, Salary, IsActive)
        SELECT
            StaffID,
            CONCAT('Test Staff ', StaffID, ' ', LEFT(CONVERT(VARCHAR(36), NEWID()), 8)),
            Position,
            Branch,
            CONCAT('01', RIGHT('00000000' + CONVERT(VARCHAR(8), ABS(CHECKSUM(NEWID())) % 100000000), 8)),
            CONVERT(DECIMAL(15,2), 3000 + ABS(CHECKSUM(NEWID())) % 7000),
            IsActive
        FROM dbo.Staff;

        COMMIT TRANSACTION;
    END TRY
    BEGIN CATCH
        IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION;
        THROW;
    END CATCH
END;
GO

GRANT EXECUTE ON dbo.sp_RefreshDevData TO DBA;
GRANT SELECT ON SCHEMA::Sanitized TO DBA;
DENY SELECT, INSERT, UPDATE, DELETE ON SCHEMA::Sanitized TO Bank_Manager, Bank_Officer, Customer;
GO

CREATE SCHEMA Analytics AUTHORIZATION dbo;
GO

CREATE TABLE Analytics.Account_Anonymized (
    AccountID INT NOT NULL PRIMARY KEY,
    SurrogateCustomerID UNIQUEIDENTIFIER NOT NULL,
    AccountType NVARCHAR(20) NOT NULL,
    Balance DECIMAL(15,2) NOT NULL,
    IsActive BIT NOT NULL
);
GO

CREATE TABLE Analytics.TransactionRecord_Anonymized (
    TransID INT NOT NULL PRIMARY KEY,
    AccountID INT NOT NULL,
    TransDate DATETIME2 NOT NULL,
    Amount DECIMAL(15,2) NOT NULL,
    TransactionType NVARCHAR(20) NOT NULL,
    ToAccountID INT NULL
);
GO

-- C5: one random surrogate is generated per real customer for each refresh.
-- No CustomerID, name, IC number, phone, or address is copied to analytics.
CREATE OR ALTER PROCEDURE dbo.sp_RefreshAnalyticsData
WITH EXECUTE AS OWNER
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    BEGIN TRY
        BEGIN TRANSACTION;

        IF OBJECT_ID('tempdb..#SurrogateMap') IS NOT NULL DROP TABLE #SurrogateMap;
        SELECT CustomerID AS RealCustomerID, NEWID() AS SurrogateCustomerID
        INTO #SurrogateMap
        FROM (SELECT DISTINCT CustomerID FROM dbo.Account) AS DistinctCustomers;

        TRUNCATE TABLE Analytics.TransactionRecord_Anonymized;
        TRUNCATE TABLE Analytics.Account_Anonymized;

        INSERT INTO Analytics.Account_Anonymized
            (AccountID, SurrogateCustomerID, AccountType, Balance, IsActive)
        SELECT a.AccountID, m.SurrogateCustomerID, a.AccountType, a.Balance, a.IsActive
        FROM dbo.Account a
        JOIN #SurrogateMap m ON m.RealCustomerID = a.CustomerID;

        INSERT INTO Analytics.TransactionRecord_Anonymized
            (TransID, AccountID, TransDate, Amount, TransactionType, ToAccountID)
        SELECT TransID, AccountID, TransDate, Amount, TransactionType, ToAccountID
        FROM dbo.TransactionRecord;

        DROP TABLE #SurrogateMap;
        COMMIT TRANSACTION;
    END TRY
    BEGIN CATCH
        IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION;
        THROW;
    END CATCH
END;
GO

GRANT EXECUTE ON dbo.sp_RefreshAnalyticsData TO DBA;
GRANT SELECT ON SCHEMA::Analytics TO DBA;
DENY SELECT, INSERT, UPDATE, DELETE ON SCHEMA::Analytics TO Bank_Manager, Bank_Officer, Customer;
GO

PRINT 'C4/C5 - static masking and anonymised analytics staging controls created.';
GO

-- PART 7: DML audit triggers -- log every INSERT/UPDATE/DELETE on the business tables. Integrity.

USE SmartBankDB;
GO

-- AuditLog already has its final RecordID/Activity schema, and
-- fn_GetSessionUsername is created before authentication procedures in Part 1.
-- This avoids the former clean-deployment dependency failure.


-- trg_Staff_Audit: logs all Staff changes. Integrity.
CREATE OR ALTER TRIGGER dbo.trg_Staff_Audit
ON dbo.Staff
WITH EXECUTE AS OWNER
AFTER INSERT, UPDATE, DELETE
AS
BEGIN
    SET NOCOUNT ON;
    DECLARE @Who NVARCHAR(150) = dbo.fn_GetSessionUsername();

    IF EXISTS (SELECT 1 FROM INSERTED) AND EXISTS (SELECT 1 FROM DELETED)
    BEGIN
        -- UPDATE: one AuditLog row per column that actually changed,
        -- Activity holds "old -> new" for every column, consistently
        INSERT INTO AuditSchema.AuditLog (TableName, ColumnName, RecordID, ChangedBy, ActionType, Activity)
        SELECT 'Staff', 'StaffName', CONVERT(NVARCHAR(50), i.StaffID), @Who, 'UPDATE', CONCAT(ISNULL(d.StaffName, 'NULL'), ' -> ', ISNULL(i.StaffName, 'NULL'))
        FROM INSERTED i JOIN DELETED d ON i.StaffID = d.StaffID
        WHERE ISNULL(i.StaffName, N'~NULL~') <> ISNULL(d.StaffName, N'~NULL~')
        UNION ALL
        SELECT 'Staff', 'Position', CONVERT(NVARCHAR(50), i.StaffID), @Who, 'UPDATE', CONCAT(ISNULL(d.Position, 'NULL'), ' -> ', ISNULL(i.Position, 'NULL'))
        FROM INSERTED i JOIN DELETED d ON i.StaffID = d.StaffID
        WHERE ISNULL(i.Position, N'~NULL~') <> ISNULL(d.Position, N'~NULL~')
        UNION ALL
        SELECT 'Staff', 'Branch', CONVERT(NVARCHAR(50), i.StaffID), @Who, 'UPDATE', CONCAT(ISNULL(d.Branch, 'NULL'), ' -> ', ISNULL(i.Branch, 'NULL'))
        FROM INSERTED i JOIN DELETED d ON i.StaffID = d.StaffID
        WHERE ISNULL(i.Branch, N'~NULL~') <> ISNULL(d.Branch, N'~NULL~')
        UNION ALL
        SELECT 'Staff', 'Phone', CONVERT(NVARCHAR(50), i.StaffID), @Who, 'UPDATE', CONCAT(ISNULL(d.Phone, 'NULL'), ' -> ', ISNULL(i.Phone, 'NULL'))
        FROM INSERTED i JOIN DELETED d ON i.StaffID = d.StaffID
        WHERE ISNULL(i.Phone, N'~NULL~') <> ISNULL(d.Phone, N'~NULL~')
        UNION ALL
        SELECT 'Staff', 'Salary', CONVERT(NVARCHAR(50), i.StaffID), @Who, 'UPDATE', CONCAT(CONVERT(NVARCHAR(30), d.Salary), ' -> ', CONVERT(NVARCHAR(30), i.Salary))
        FROM INSERTED i JOIN DELETED d ON i.StaffID = d.StaffID
        WHERE ISNULL(d.Salary, -1) <> ISNULL(i.Salary, -1)
        UNION ALL
        SELECT 'Staff', 'IsActive', CONVERT(NVARCHAR(50), i.StaffID), @Who, 'UPDATE',
               CONCAT(CASE WHEN d.IsActive = 1 THEN 'Active' ELSE 'Inactive' END, ' -> ', CASE WHEN i.IsActive = 1 THEN 'Active' ELSE 'Inactive' END)
        FROM INSERTED i JOIN DELETED d ON i.StaffID = d.StaffID
        WHERE ISNULL(d.IsActive, -1) <> ISNULL(i.IsActive, -1);
    END
    ELSE IF EXISTS (SELECT 1 FROM INSERTED)
    BEGIN
        INSERT INTO AuditSchema.AuditLog (TableName, ColumnName, RecordID, ChangedBy, ActionType, Activity)
        SELECT 'Staff', NULL, CONVERT(NVARCHAR(50), StaffID), @Who, 'INSERT',
               CONCAT('StaffName=', StaffName, '; Position=', Position, '; Branch=', Branch, '; Phone=', Phone, '; Salary=', Salary, '; IsActive=', CASE WHEN IsActive = 1 THEN 'Active' ELSE 'Inactive' END)
        FROM INSERTED;
    END
    ELSE
    BEGIN
        INSERT INTO AuditSchema.AuditLog (TableName, ColumnName, RecordID, ChangedBy, ActionType, Activity)
        SELECT 'Staff', NULL, CONVERT(NVARCHAR(50), StaffID), @Who, 'DELETE',
               CONCAT('StaffName=', StaffName, '; Position=', Position, '; Branch=', Branch, '; Phone=', Phone, '; Salary=', Salary, '; IsActive=', CASE WHEN IsActive = 1 THEN 'Active' ELSE 'Inactive' END)
        FROM DELETED;
    END
END;
GO


-- trg_Customer_Audit: logs Customer changes; ICNumber changes are flagged, never shown in plaintext. Confidentiality + Integrity.
CREATE OR ALTER TRIGGER dbo.trg_Customer_Audit
ON dbo.Customer
WITH EXECUTE AS OWNER
AFTER INSERT, UPDATE, DELETE
AS
BEGIN
    SET NOCOUNT ON;
    DECLARE @Who NVARCHAR(150) = dbo.fn_GetSessionUsername();

    IF EXISTS (SELECT 1 FROM INSERTED) AND EXISTS (SELECT 1 FROM DELETED)
    BEGIN
        INSERT INTO AuditSchema.AuditLog (TableName, ColumnName, RecordID, ChangedBy, ActionType, Activity)
        SELECT 'Customer', 'CustomerName', CONVERT(NVARCHAR(50), i.CustomerID), @Who, 'UPDATE', CONCAT(ISNULL(d.CustomerName, 'NULL'), ' -> ', ISNULL(i.CustomerName, 'NULL'))
        FROM INSERTED i JOIN DELETED d ON i.CustomerID = d.CustomerID
        WHERE ISNULL(i.CustomerName, N'~NULL~') <> ISNULL(d.CustomerName, N'~NULL~')
        UNION ALL
        SELECT 'Customer', 'Phone', CONVERT(NVARCHAR(50), i.CustomerID), @Who, 'UPDATE', CONCAT(ISNULL(d.Phone, 'NULL'), ' -> ', ISNULL(i.Phone, 'NULL'))
        FROM INSERTED i JOIN DELETED d ON i.CustomerID = d.CustomerID
        WHERE ISNULL(i.Phone, N'~NULL~') <> ISNULL(d.Phone, N'~NULL~')
        UNION ALL
        SELECT 'Customer', 'Address', CONVERT(NVARCHAR(50), i.CustomerID), @Who, 'UPDATE', CONCAT(ISNULL(d.Address, 'NULL'), ' -> ', ISNULL(i.Address, 'NULL'))
        FROM INSERTED i JOIN DELETED d ON i.CustomerID = d.CustomerID
        WHERE ISNULL(i.Address, N'~NULL~') <> ISNULL(d.Address, N'~NULL~')
        UNION ALL
        SELECT 'Customer', 'IsActive', CONVERT(NVARCHAR(50), i.CustomerID), @Who, 'UPDATE',
               CONCAT(CASE WHEN d.IsActive = 1 THEN 'Active' ELSE 'Inactive' END, ' -> ', CASE WHEN i.IsActive = 1 THEN 'Active' ELSE 'Inactive' END)
        FROM INSERTED i JOIN DELETED d ON i.CustomerID = d.CustomerID
        WHERE ISNULL(d.IsActive, -1) <> ISNULL(i.IsActive, -1)
        UNION ALL
        SELECT 'Customer', 'ICNumber', CONVERT(NVARCHAR(50), i.CustomerID), @Who, 'UPDATE', '<encrypted value changed>'
        FROM INSERTED i JOIN DELETED d ON i.CustomerID = d.CustomerID
        WHERE i.ICNumber <> d.ICNumber;
    END
    ELSE IF EXISTS (SELECT 1 FROM INSERTED)
    BEGIN
        INSERT INTO AuditSchema.AuditLog (TableName, ColumnName, RecordID, ChangedBy, ActionType, Activity)
        SELECT 'Customer', NULL, CONVERT(NVARCHAR(50), CustomerID), @Who, 'INSERT',
               CONCAT('CustomerName=', CustomerName, '; Phone=', Phone, '; Address=', Address, '; IsActive=', CASE WHEN IsActive = 1 THEN 'Active' ELSE 'Inactive' END, '; ICNumber=<encrypted>')
        FROM INSERTED;
    END
    ELSE
    BEGIN
        INSERT INTO AuditSchema.AuditLog (TableName, ColumnName, RecordID, ChangedBy, ActionType, Activity)
        SELECT 'Customer', NULL, CONVERT(NVARCHAR(50), CustomerID), @Who, 'DELETE',
               CONCAT('CustomerName=', CustomerName, '; Phone=', Phone, '; Address=', Address, '; IsActive=', CASE WHEN IsActive = 1 THEN 'Active' ELSE 'Inactive' END, '; ICNumber=<encrypted>')
        FROM DELETED;
    END
END;
GO


-- trg_Account_Audit: logs all Account changes. Integrity.
CREATE OR ALTER TRIGGER dbo.trg_Account_Audit
ON dbo.Account
WITH EXECUTE AS OWNER
AFTER INSERT, UPDATE, DELETE
AS
BEGIN
    SET NOCOUNT ON;
    DECLARE @Who NVARCHAR(150) = dbo.fn_GetSessionUsername();

    IF EXISTS (SELECT 1 FROM INSERTED) AND EXISTS (SELECT 1 FROM DELETED)
    BEGIN
        INSERT INTO AuditSchema.AuditLog (TableName, ColumnName, RecordID, ChangedBy, ActionType, Activity)
        SELECT 'Account', 'CustomerID', CONVERT(NVARCHAR(50), i.AccountID), @Who, 'UPDATE', CONCAT(CONVERT(NVARCHAR(50), d.CustomerID), ' -> ', CONVERT(NVARCHAR(50), i.CustomerID))
        FROM INSERTED i JOIN DELETED d ON i.AccountID = d.AccountID
        WHERE ISNULL(d.CustomerID, -1) <> ISNULL(i.CustomerID, -1)
        UNION ALL
        SELECT 'Account', 'AccountType', CONVERT(NVARCHAR(50), i.AccountID), @Who, 'UPDATE', CONCAT(ISNULL(d.AccountType, 'NULL'), ' -> ', ISNULL(i.AccountType, 'NULL'))
        FROM INSERTED i JOIN DELETED d ON i.AccountID = d.AccountID
        WHERE ISNULL(i.AccountType, N'~NULL~') <> ISNULL(d.AccountType, N'~NULL~')
        UNION ALL
        SELECT 'Account', 'Balance', CONVERT(NVARCHAR(50), i.AccountID), @Who, 'UPDATE', CONCAT(CONVERT(NVARCHAR(30), d.Balance), ' -> ', CONVERT(NVARCHAR(30), i.Balance))
        FROM INSERTED i JOIN DELETED d ON i.AccountID = d.AccountID
        WHERE ISNULL(d.Balance, -1) <> ISNULL(i.Balance, -1)
        UNION ALL
        SELECT 'Account', 'IsActive', CONVERT(NVARCHAR(50), i.AccountID), @Who, 'UPDATE',
               CONCAT(CASE WHEN d.IsActive = 1 THEN 'Active' ELSE 'Inactive' END, ' -> ', CASE WHEN i.IsActive = 1 THEN 'Active' ELSE 'Inactive' END)
        FROM INSERTED i JOIN DELETED d ON i.AccountID = d.AccountID
        WHERE ISNULL(d.IsActive, -1) <> ISNULL(i.IsActive, -1);
    END
    ELSE IF EXISTS (SELECT 1 FROM INSERTED)
    BEGIN
        INSERT INTO AuditSchema.AuditLog (TableName, ColumnName, RecordID, ChangedBy, ActionType, Activity)
        SELECT 'Account', NULL, CONVERT(NVARCHAR(50), AccountID), @Who, 'INSERT',
               CONCAT('CustomerID=', CustomerID, '; AccountType=', AccountType, '; Balance=', Balance, '; IsActive=', CASE WHEN IsActive = 1 THEN 'Active' ELSE 'Inactive' END)
        FROM INSERTED;
    END
    ELSE
    BEGIN
        INSERT INTO AuditSchema.AuditLog (TableName, ColumnName, RecordID, ChangedBy, ActionType, Activity)
        SELECT 'Account', NULL, CONVERT(NVARCHAR(50), AccountID), @Who, 'DELETE',
               CONCAT('CustomerID=', CustomerID, '; AccountType=', AccountType, '; Balance=', Balance, '; IsActive=', CASE WHEN IsActive = 1 THEN 'Active' ELSE 'Inactive' END)
        FROM DELETED;
    END
END;
GO


-- trg_TransactionRecord_Audit: logs all changes; an UPDATE/DELETE here is itself suspicious, since transactions should be insert-only. Integrity.
CREATE OR ALTER TRIGGER dbo.trg_TransactionRecord_Audit
ON dbo.TransactionRecord
WITH EXECUTE AS OWNER
AFTER INSERT, UPDATE, DELETE
AS
BEGIN
    SET NOCOUNT ON;
    DECLARE @Who NVARCHAR(150) = dbo.fn_GetSessionUsername();

    IF EXISTS (SELECT 1 FROM INSERTED) AND EXISTS (SELECT 1 FROM DELETED)
    BEGIN
        INSERT INTO AuditSchema.AuditLog (TableName, ColumnName, RecordID, ChangedBy, ActionType, Activity)
        SELECT 'TransactionRecord', 'Amount', CONVERT(NVARCHAR(50), i.TransID), @Who, 'UPDATE', CONCAT(CONVERT(NVARCHAR(30), d.Amount), ' -> ', CONVERT(NVARCHAR(30), i.Amount))
        FROM INSERTED i JOIN DELETED d ON i.TransID = d.TransID
        WHERE ISNULL(d.Amount, -1) <> ISNULL(i.Amount, -1)
        UNION ALL
        SELECT 'TransactionRecord', 'TransactionType', CONVERT(NVARCHAR(50), i.TransID), @Who, 'UPDATE', CONCAT(ISNULL(d.TransactionType, 'NULL'), ' -> ', ISNULL(i.TransactionType, 'NULL'))
        FROM INSERTED i JOIN DELETED d ON i.TransID = d.TransID
        WHERE ISNULL(i.TransactionType, N'~NULL~') <> ISNULL(d.TransactionType, N'~NULL~')
        UNION ALL
        SELECT 'TransactionRecord', 'AccountID', CONVERT(NVARCHAR(50), i.TransID), @Who, 'UPDATE', CONCAT(CONVERT(NVARCHAR(50), d.AccountID), ' -> ', CONVERT(NVARCHAR(50), i.AccountID))
        FROM INSERTED i JOIN DELETED d ON i.TransID = d.TransID
        WHERE ISNULL(d.AccountID, -1) <> ISNULL(i.AccountID, -1)
        UNION ALL
        SELECT 'TransactionRecord', 'ToAccountID', CONVERT(NVARCHAR(50), i.TransID), @Who, 'UPDATE', CONCAT(ISNULL(CONVERT(NVARCHAR(50), d.ToAccountID), 'NULL'), ' -> ', ISNULL(CONVERT(NVARCHAR(50), i.ToAccountID), 'NULL'))
        FROM INSERTED i JOIN DELETED d ON i.TransID = d.TransID
        WHERE ISNULL(d.ToAccountID, -1) <> ISNULL(i.ToAccountID, -1);
    END
    ELSE IF EXISTS (SELECT 1 FROM INSERTED)
    BEGIN
        INSERT INTO AuditSchema.AuditLog (TableName, ColumnName, RecordID, ChangedBy, ActionType, Activity)
        SELECT 'TransactionRecord', NULL, CONVERT(NVARCHAR(50), TransID), @Who, 'INSERT',
               CONCAT('AccountID=', AccountID, '; ToAccountID=', ISNULL(CONVERT(NVARCHAR(20), ToAccountID), 'NULL'), '; Amount=', Amount, '; TransactionType=', TransactionType)
        FROM INSERTED;
    END
    ELSE
    BEGIN
        INSERT INTO AuditSchema.AuditLog (TableName, ColumnName, RecordID, ChangedBy, ActionType, Activity)
        SELECT 'TransactionRecord', NULL, CONVERT(NVARCHAR(50), TransID), @Who, 'DELETE',
               CONCAT('AccountID=', AccountID, '; ToAccountID=', ISNULL(CONVERT(NVARCHAR(20), ToAccountID), 'NULL'), '; Amount=', Amount, '; TransactionType=', TransactionType)
        FROM DELETED;
    END
END;
GO


-- trg_PendingApproval_Audit: logs all PendingApproval changes. Integrity.
CREATE OR ALTER TRIGGER dbo.trg_PendingApproval_Audit
ON dbo.PendingApproval
WITH EXECUTE AS OWNER
AFTER INSERT, UPDATE, DELETE
AS
BEGIN
    SET NOCOUNT ON;
    DECLARE @Who NVARCHAR(150) = dbo.fn_GetSessionUsername();

    IF EXISTS (SELECT 1 FROM INSERTED) AND EXISTS (SELECT 1 FROM DELETED)
    BEGIN
        INSERT INTO AuditSchema.AuditLog (TableName, ColumnName, RecordID, ChangedBy, ActionType, Activity)
        SELECT 'PendingApproval', 'Status', CONVERT(NVARCHAR(50), i.RequestID), @Who, 'UPDATE', CONCAT(ISNULL(d.Status, 'NULL'), ' -> ', ISNULL(i.Status, 'NULL'))
        FROM INSERTED i JOIN DELETED d ON i.RequestID = d.RequestID
        WHERE ISNULL(i.Status, N'~NULL~') <> ISNULL(d.Status, N'~NULL~')
        UNION ALL
        SELECT 'PendingApproval', 'ApprovedBy', CONVERT(NVARCHAR(50), i.RequestID), @Who, 'UPDATE', CONCAT(ISNULL(d.ApprovedBy, 'NULL'), ' -> ', ISNULL(i.ApprovedBy, 'NULL'))
        FROM INSERTED i JOIN DELETED d ON i.RequestID = d.RequestID
        WHERE ISNULL(i.ApprovedBy, N'~NULL~') <> ISNULL(d.ApprovedBy, N'~NULL~')
        UNION ALL
        SELECT 'PendingApproval', 'ApprovalDate', CONVERT(NVARCHAR(50), i.RequestID), @Who, 'UPDATE', CONCAT(ISNULL(CONVERT(NVARCHAR(30), d.ApprovalDate), 'NULL'), ' -> ', ISNULL(CONVERT(NVARCHAR(30), i.ApprovalDate), 'NULL'))
        FROM INSERTED i JOIN DELETED d ON i.RequestID = d.RequestID
        WHERE ISNULL(CONVERT(NVARCHAR(30), i.ApprovalDate), N'~NULL~') <> ISNULL(CONVERT(NVARCHAR(30), d.ApprovalDate), N'~NULL~');
    END
    ELSE IF EXISTS (SELECT 1 FROM INSERTED)
    BEGIN
        INSERT INTO AuditSchema.AuditLog (TableName, ColumnName, RecordID, ChangedBy, ActionType, Activity)
        SELECT 'PendingApproval', NULL, CONVERT(NVARCHAR(50), RequestID), @Who, 'INSERT',
               CONCAT('AccountID=', AccountID, '; RequestedBy=', RequestedBy, '; Amount=', Amount, '; TransactionType=', TransactionType, '; Status=', Status)
        FROM INSERTED;
    END
    ELSE
    BEGIN
        INSERT INTO AuditSchema.AuditLog (TableName, ColumnName, RecordID, ChangedBy, ActionType, Activity)
        SELECT 'PendingApproval', NULL, CONVERT(NVARCHAR(50), RequestID), @Who, 'DELETE',
               CONCAT('AccountID=', AccountID, '; RequestedBy=', RequestedBy, '; Amount=', Amount, '; TransactionType=', TransactionType, '; Status=', Status)
        FROM DELETED;
    END
END;
GO


-- trg_UserLogin_Audit: logs all UserLogin changes, including lockout/failed-attempt fields C6's native audit can't see. Confidentiality + Integrity.
CREATE OR ALTER TRIGGER dbo.trg_UserLogin_Audit
ON dbo.UserLogin
WITH EXECUTE AS OWNER
AFTER INSERT, UPDATE, DELETE
AS
BEGIN
    SET NOCOUNT ON;
    DECLARE @Who NVARCHAR(150) = dbo.fn_GetSessionUsername();

    IF EXISTS (SELECT 1 FROM INSERTED) AND EXISTS (SELECT 1 FROM DELETED)
    BEGIN
        INSERT INTO AuditSchema.AuditLog (TableName, ColumnName, RecordID, ChangedBy, ActionType, Activity)
        SELECT 'UserLogin', 'PasswordHash', CONVERT(NVARCHAR(50), i.LoginID), @Who, 'UPDATE', '<hash changed>'
        FROM INSERTED i JOIN DELETED d ON i.LoginID = d.LoginID
        WHERE i.PasswordHash <> d.PasswordHash
        UNION ALL
        SELECT 'UserLogin', 'Salt', CONVERT(NVARCHAR(50), i.LoginID), @Who, 'UPDATE', '<hash changed>'
        FROM INSERTED i JOIN DELETED d ON i.LoginID = d.LoginID
        WHERE i.Salt <> d.Salt
        UNION ALL
        SELECT 'UserLogin', 'IsActive', CONVERT(NVARCHAR(50), i.LoginID), @Who, 'UPDATE',
               CONCAT(CASE WHEN d.IsActive = 1 THEN 'Active' ELSE 'Inactive' END, ' -> ', CASE WHEN i.IsActive = 1 THEN 'Active' ELSE 'Inactive' END)
        FROM INSERTED i JOIN DELETED d ON i.LoginID = d.LoginID
        WHERE ISNULL(d.IsActive, -1) <> ISNULL(i.IsActive, -1)
        UNION ALL
        SELECT 'UserLogin', 'FailedLoginAttempts', CONVERT(NVARCHAR(50), i.LoginID), @Who, 'UPDATE', CONCAT(CONVERT(NVARCHAR(10), d.FailedLoginAttempts), ' -> ', CONVERT(NVARCHAR(10), i.FailedLoginAttempts))
        FROM INSERTED i JOIN DELETED d ON i.LoginID = d.LoginID
        WHERE ISNULL(d.FailedLoginAttempts, -1) <> ISNULL(i.FailedLoginAttempts, -1)
        UNION ALL
        SELECT 'UserLogin', 'LockoutUntil', CONVERT(NVARCHAR(50), i.LoginID), @Who, 'UPDATE', CONCAT(ISNULL(CONVERT(NVARCHAR(30), d.LockoutUntil), 'NULL'), ' -> ', ISNULL(CONVERT(NVARCHAR(30), i.LockoutUntil), 'NULL'))
        FROM INSERTED i JOIN DELETED d ON i.LoginID = d.LoginID
        WHERE ISNULL(CONVERT(NVARCHAR(30), i.LockoutUntil), N'~NULL~') <> ISNULL(CONVERT(NVARCHAR(30), d.LockoutUntil), N'~NULL~')
        UNION ALL
        SELECT 'UserLogin', 'LastLogin', CONVERT(NVARCHAR(50), i.LoginID), @Who, 'UPDATE', CONCAT(ISNULL(CONVERT(NVARCHAR(30), d.LastLogin), 'NULL'), ' -> ', ISNULL(CONVERT(NVARCHAR(30), i.LastLogin), 'NULL'))
        FROM INSERTED i JOIN DELETED d ON i.LoginID = d.LoginID
        WHERE ISNULL(CONVERT(NVARCHAR(30), i.LastLogin), N'~NULL~') <> ISNULL(CONVERT(NVARCHAR(30), d.LastLogin), N'~NULL~')
        UNION ALL
        SELECT 'UserLogin', 'PasswordLastChanged', CONVERT(NVARCHAR(50), i.LoginID), @Who, 'UPDATE', CONCAT(CONVERT(NVARCHAR(30), d.PasswordLastChanged), ' -> ', CONVERT(NVARCHAR(30), i.PasswordLastChanged))
        FROM INSERTED i JOIN DELETED d ON i.LoginID = d.LoginID
        WHERE ISNULL(CONVERT(NVARCHAR(30), i.PasswordLastChanged), N'~NULL~') <> ISNULL(CONVERT(NVARCHAR(30), d.PasswordLastChanged), N'~NULL~');
    END
    ELSE IF EXISTS (SELECT 1 FROM INSERTED)
    BEGIN
        INSERT INTO AuditSchema.AuditLog (TableName, ColumnName, RecordID, ChangedBy, ActionType, Activity)
        SELECT 'UserLogin', NULL, CONVERT(NVARCHAR(50), LoginID), @Who, 'INSERT',
               CONCAT('Username=', Username, '; UserType=', UserType, '; IsActive=', CASE WHEN IsActive = 1 THEN 'Active' ELSE 'Inactive' END, '; PasswordHash=<hash>; Salt=<hash>')
        FROM INSERTED;
    END
    ELSE
    BEGIN
        INSERT INTO AuditSchema.AuditLog (TableName, ColumnName, RecordID, ChangedBy, ActionType, Activity)
        SELECT 'UserLogin', NULL, CONVERT(NVARCHAR(50), LoginID), @Who, 'DELETE',
               CONCAT('Username=', Username, '; UserType=', UserType, '; IsActive=', CASE WHEN IsActive = 1 THEN 'Active' ELSE 'Inactive' END, '; PasswordHash=<hash>; Salt=<hash>')
        FROM DELETED;
    END
END;
GO


-- trg_SecurityConfig_Audit: logs policy-value changes (keyed by ConfigKey, not an int ID). Integrity.
CREATE OR ALTER TRIGGER dbo.trg_SecurityConfig_Audit
ON dbo.SecurityConfig
WITH EXECUTE AS OWNER
AFTER INSERT, UPDATE, DELETE
AS
BEGIN
    SET NOCOUNT ON;
    DECLARE @Who NVARCHAR(150) = dbo.fn_GetSessionUsername();

    IF EXISTS (SELECT 1 FROM INSERTED) AND EXISTS (SELECT 1 FROM DELETED)
    BEGIN
        INSERT INTO AuditSchema.AuditLog (TableName, ColumnName, RecordID, ChangedBy, ActionType, Activity)
        SELECT 'SecurityConfig', 'ConfigValue', i.ConfigKey, @Who, 'UPDATE', CONCAT(CONVERT(NVARCHAR(20), d.ConfigValue), ' -> ', CONVERT(NVARCHAR(20), i.ConfigValue))
        FROM INSERTED i JOIN DELETED d ON i.ConfigKey = d.ConfigKey
        WHERE ISNULL(d.ConfigValue, -1) <> ISNULL(i.ConfigValue, -1);
    END
    ELSE IF EXISTS (SELECT 1 FROM INSERTED)
    BEGIN
        INSERT INTO AuditSchema.AuditLog (TableName, ColumnName, RecordID, ChangedBy, ActionType, Activity)
        SELECT 'SecurityConfig', NULL, ConfigKey, @Who, 'INSERT',
               CONCAT('ConfigKey=', ConfigKey, '; ConfigValue=', ConfigValue)
        FROM INSERTED;
    END
    ELSE
    BEGIN
        INSERT INTO AuditSchema.AuditLog (TableName, ColumnName, RecordID, ChangedBy, ActionType, Activity)
        SELECT 'SecurityConfig', NULL, ConfigKey, @Who, 'DELETE',
               CONCAT('ConfigKey=', ConfigKey, '; ConfigValue=', ConfigValue)
        FROM DELETED;
    END
END;
GO


-- PART 8: write-side procedures for Integrity Requirements 2-5 -- GRANT decides who can call a proc, business-rule checks inside decide what they can do with it. Integrity.

USE SmartBankDB;
GO

-- sp_ManageStaff: Manager creates/updates Bank Officer records only; Position isn't editable here. Integrity.
CREATE OR ALTER PROCEDURE dbo.sp_ManageStaff
    @StaffID    INT           = NULL,
    @StaffName  NVARCHAR(100),
    @Position   NVARCHAR(50),
    @Branch     NVARCHAR(100),
    @Phone      NVARCHAR(20),
    @Salary     DECIMAL(15,2),
    @IsActive   BIT           = 1,
    @Success    BIT OUTPUT,
    @Message    NVARCHAR(200) OUTPUT
WITH EXECUTE AS OWNER
AS
BEGIN
    SET NOCOUNT ON;
    SET @Success = 0;
    DECLARE @Who NVARCHAR(150) = dbo.fn_GetSessionUsername();

-- NULL @IsActive coalesces to the declared default (1) instead of hitting a raw constraint error. Integrity.
    SET @IsActive = ISNULL(@IsActive, 1);

-- Confirms the target record is a Bank Officer, not another Manager or DBA. Integrity.
    IF @Position IS NULL OR @Position <> 'Bank Officer'
    BEGIN
        SET @Message = 'sp_ManageStaff can only create or update Bank Officer records.';
        INSERT INTO AuditSchema.AuditLog (TableName, ColumnName, RecordID, ChangedBy, ActionType, Activity)
        VALUES ('Staff', NULL, CONVERT(NVARCHAR(50), @StaffID), @Who, 'REJECTED', @Message);
        RETURN;
    END

-- Validates required fields before they'd otherwise hit the table's own constraints. Integrity.
    IF @StaffName IS NULL OR LTRIM(RTRIM(@StaffName)) = ''
       OR @Branch IS NULL OR LTRIM(RTRIM(@Branch)) = ''
       OR @Phone IS NULL OR LTRIM(RTRIM(@Phone)) = ''
    BEGIN
        SET @Message = 'StaffName, Branch, and Phone are required.';
        INSERT INTO AuditSchema.AuditLog (TableName, ColumnName, RecordID, ChangedBy, ActionType, Activity)
        VALUES ('Staff', NULL, CONVERT(NVARCHAR(50), @StaffID), @Who, 'REJECTED', @Message);
        RETURN;
    END

    IF @Salary IS NULL OR @Salary <= 0
    BEGIN
        SET @Message = 'Salary must be a positive value.';
        INSERT INTO AuditSchema.AuditLog (TableName, ColumnName, RecordID, ChangedBy, ActionType, Activity)
        VALUES ('Staff', NULL, CONVERT(NVARCHAR(50), @StaffID), @Who, 'REJECTED', @Message);
        RETURN;
    END

    IF @StaffID IS NULL
    BEGIN
-- CREATE path.
        INSERT INTO dbo.Staff (StaffName, Position, Branch, Phone, Salary, IsActive)
        VALUES (@StaffName, @Position, @Branch, @Phone, @Salary, @IsActive);

        DECLARE @NewStaffID INT = SCOPE_IDENTITY();

-- Auto-provisions a UserLogin (temp password, forced expiry) so the new Officer can actually log in. Confidentiality + Integrity.
        DECLARE @BaseUsername NVARCHAR(50) = 'staff_' + LOWER(REPLACE(@StaffName, ' ', ''));
        DECLARE @NewUsername NVARCHAR(50) = @BaseUsername;
        IF EXISTS (SELECT 1 FROM dbo.UserLogin WHERE Username = @NewUsername)
            SET @NewUsername = @BaseUsername + CONVERT(NVARCHAR(10), @NewStaffID);

        DECLARE @TempPassword NVARCHAR(20) = CONCAT('Welcome', CONVERT(NVARCHAR(4), ABS(CHECKSUM(NEWID())) % 9000 + 1000), '!');
        DECLARE @NewLoginSalt VARBINARY(32) = CRYPT_GEN_RANDOM(32);
        DECLARE @ExpiryDaysNow INT;
        SELECT @ExpiryDaysNow = ConfigValue FROM dbo.SecurityConfig WHERE ConfigKey = 'PasswordExpiryDays';

        INSERT INTO dbo.UserLogin (Username, PasswordHash, Salt, StaffID, UserType, PasswordLastChanged, IsActive)
        VALUES (
            @NewUsername,
            dbo.fn_HashPassword(@TempPassword, @NewLoginSalt),
            @NewLoginSalt,
            @NewStaffID,
            'Staff',
            DATEADD(DAY, -(@ExpiryDaysNow + 1), SYSDATETIME()),
            @IsActive
        );

        SET @Success = 1;
        SET @Message = CONCAT('Staff record created successfully. Login provisioned -- Username: ', @NewUsername, ', Temporary password: ', @TempPassword, ' (must be changed on first login).');
    END
    ELSE
    BEGIN
-- UPDATE path: re-checks the EXISTING row's Position before allowing any change. Integrity.
        DECLARE @CurrentPosition NVARCHAR(50);
        SELECT @CurrentPosition = Position FROM dbo.Staff WHERE StaffID = @StaffID;

        IF @CurrentPosition IS NULL
        BEGIN
            SET @Message = 'No staff record found with that StaffID.';
            INSERT INTO AuditSchema.AuditLog (TableName, ColumnName, RecordID, ChangedBy, ActionType, Activity)
            VALUES ('Staff', NULL, CONVERT(NVARCHAR(50), @StaffID), @Who, 'REJECTED', @Message);
            RETURN;
        END

        IF @CurrentPosition <> 'Bank Officer'
        BEGIN
            SET @Message = 'This staff record is not a Bank Officer and is outside sp_ManageStaff''s scope.';
            INSERT INTO AuditSchema.AuditLog (TableName, ColumnName, RecordID, ChangedBy, ActionType, Activity)
            VALUES ('Staff', NULL, CONVERT(NVARCHAR(50), @StaffID), @Who, 'REJECTED', @Message);
            RETURN;
        END

        UPDATE dbo.Staff
        SET StaffName = @StaffName,
            Branch     = @Branch,
            Phone      = @Phone,
            Salary     = @Salary,
            IsActive   = @IsActive
            -- Position intentionally NOT included -- see header note
        WHERE StaffID = @StaffID;

        SET @Success = 1;
        SET @Message = 'Staff record updated successfully.';
    END
END;
GO

-- Layer 1 -- only Bank_Manager can call this at all. Integrity.
GRANT EXECUTE ON dbo.sp_ManageStaff TO Bank_Manager;
GO


-- sp_ManageCustomer: Officer creates/updates Customer records; first real use of CLE encryption; ICNumber isn't editable here. Confidentiality + Integrity.
CREATE OR ALTER PROCEDURE dbo.sp_ManageCustomer
    @CustomerID    INT           = NULL,
    @CustomerName  NVARCHAR(100),
    @ICNumber      NVARCHAR(20)  = NULL,  -- plaintext, CREATE only -- ignored on UPDATE
    @Phone         NVARCHAR(20),
    @Address       NVARCHAR(255),
    @IsActive      BIT           = 1,
    @Success       BIT OUTPUT,
    @Message       NVARCHAR(200) OUTPUT
WITH EXECUTE AS OWNER
AS
BEGIN
    SET NOCOUNT ON;
    SET @Success = 0;
    DECLARE @Who NVARCHAR(150) = dbo.fn_GetSessionUsername();

    -- Customer.IsActive is NOT NULL -- same reasoning and same fix
    -- as sp_ManageStaff's equivalent coalesce
    SET @IsActive = ISNULL(@IsActive, 1);

-- Input validation shared by both CREATE and UPDATE.
    IF @CustomerName IS NULL OR LTRIM(RTRIM(@CustomerName)) = ''
       OR @Phone IS NULL OR LTRIM(RTRIM(@Phone)) = ''
       OR @Address IS NULL OR LTRIM(RTRIM(@Address)) = ''
    BEGIN
        SET @Message = 'CustomerName, Phone, and Address are required.';
        INSERT INTO AuditSchema.AuditLog (TableName, ColumnName, RecordID, ChangedBy, ActionType, Activity)
        VALUES ('Customer', NULL, CONVERT(NVARCHAR(50), @CustomerID), @Who, 'REJECTED', @Message);
        RETURN;
    END

    IF @CustomerID IS NULL
    BEGIN
-- CREATE path.
        IF @ICNumber IS NULL OR LEN(@ICNumber) <> 12 OR @ICNumber LIKE '%[^0-9]%'
        BEGIN
            SET @Message = 'ICNumber is required and must be exactly 12 digits.';
            INSERT INTO AuditSchema.AuditLog (TableName, ColumnName, RecordID, ChangedBy, ActionType, Activity)
            VALUES ('Customer', NULL, NULL, @Who, 'REJECTED', @Message);
            RETURN;
        END

        DECLARE @ICHash VARBINARY(32) = HASHBYTES('SHA2_256', @ICNumber);

        IF EXISTS (SELECT 1 FROM dbo.Customer WHERE ICNumberHash = @ICHash)
        BEGIN
            SET @Message = 'A customer record already exists for that IC number.';
            INSERT INTO AuditSchema.AuditLog (TableName, ColumnName, RecordID, ChangedBy, ActionType, Activity)
            VALUES ('Customer', NULL, NULL, @Who, 'REJECTED', @Message);
            RETURN;
        END

-- Encrypts the new IC number with the real CLE key, not the seed data's placeholder. Confidentiality.
        OPEN SYMMETRIC KEY CLE_ICNumber_SymKey
            DECRYPTION BY CERTIFICATE CLE_ICNumber_Cert;

        DECLARE @EncryptedIC VARBINARY(MAX) = EncryptByKey(
            Key_GUID('CLE_ICNumber_SymKey'),
            CONVERT(VARBINARY(MAX), @ICNumber)
        );

        CLOSE SYMMETRIC KEY CLE_ICNumber_SymKey;

        INSERT INTO dbo.Customer (CustomerName, ICNumber, ICNumberHash, Phone, Address, IsActive)
        VALUES (@CustomerName, @EncryptedIC, @ICHash, @Phone, @Address, @IsActive);

        DECLARE @NewCustID INT = SCOPE_IDENTITY();

-- Auto-provisions a UserLogin, same temp-password pattern as sp_ManageStaff. Confidentiality + Integrity.
        DECLARE @BaseCustUsername NVARCHAR(50) = 'cust_' + LOWER(REPLACE(@CustomerName, ' ', ''));
        DECLARE @NewCustUsername NVARCHAR(50) = @BaseCustUsername;
        IF EXISTS (SELECT 1 FROM dbo.UserLogin WHERE Username = @NewCustUsername)
            SET @NewCustUsername = @BaseCustUsername + CONVERT(NVARCHAR(10), @NewCustID);

        DECLARE @CustTempPassword NVARCHAR(20) = CONCAT('Welcome', CONVERT(NVARCHAR(4), ABS(CHECKSUM(NEWID())) % 9000 + 1000), '!');
        DECLARE @CustNewSalt VARBINARY(32) = CRYPT_GEN_RANDOM(32);
        DECLARE @CustExpiryDaysNow INT;
        SELECT @CustExpiryDaysNow = ConfigValue FROM dbo.SecurityConfig WHERE ConfigKey = 'PasswordExpiryDays';

        INSERT INTO dbo.UserLogin (Username, PasswordHash, Salt, CustomerID, UserType, PasswordLastChanged, IsActive)
        VALUES (
            @NewCustUsername,
            dbo.fn_HashPassword(@CustTempPassword, @CustNewSalt),
            @CustNewSalt,
            @NewCustID,
            'Customer',
            DATEADD(DAY, -(@CustExpiryDaysNow + 1), SYSDATETIME()),
            @IsActive
        );

        SET @Success = 1;
        SET @Message = CONCAT('Customer record created successfully. Login provisioned -- Username: ', @NewCustUsername, ', Temporary password: ', @CustTempPassword, ' (must be changed on first login).');
    END
    ELSE
    BEGIN
-- UPDATE path.
        IF NOT EXISTS (SELECT 1 FROM dbo.Customer WHERE CustomerID = @CustomerID)
        BEGIN
            SET @Message = 'No customer record found with that CustomerID.';
            INSERT INTO AuditSchema.AuditLog (TableName, ColumnName, RecordID, ChangedBy, ActionType, Activity)
            VALUES ('Customer', NULL, CONVERT(NVARCHAR(50), @CustomerID), @Who, 'REJECTED', @Message);
            RETURN;
        END

        UPDATE dbo.Customer
        SET CustomerName = @CustomerName,
            Phone         = @Phone,
            Address       = @Address,
            IsActive      = @IsActive
            -- ICNumber intentionally NOT included -- see header note
        WHERE CustomerID = @CustomerID;

        SET @Success = 1;
        SET @Message = 'Customer record updated successfully.';
    END
END;
GO

-- Layer 1 -- only Bank_Officer can call this at all. Integrity.
GRANT EXECUTE ON dbo.sp_ManageCustomer TO Bank_Officer;
GO


-- sp_ManageAccount: Officer creates/updates Account records; has NO @Balance parameter at all -- only sp_ProcessTransaction can move money. Integrity.
CREATE OR ALTER PROCEDURE dbo.sp_ManageAccount
    @AccountID     INT           = NULL,
    @CustomerID    INT           = NULL,  -- required for CREATE, ignored for UPDATE
    @AccountType   NVARCHAR(20),
    @IsActive      BIT           = 1,
    @Success       BIT OUTPUT,
    @Message       NVARCHAR(200) OUTPUT
WITH EXECUTE AS OWNER
AS
BEGIN
    SET NOCOUNT ON;
    SET @Success = 0;
    DECLARE @Who NVARCHAR(150) = dbo.fn_GetSessionUsername();

-- NULL @IsActive coalesces to the declared default (1); also protects the 'no closing with a balance' check below. Integrity.
    SET @IsActive = ISNULL(@IsActive, 1);

-- Input validation shared by both CREATE and UPDATE.
    IF @AccountType IS NULL OR @AccountType NOT IN ('Savings', 'Current', 'Fixed Deposit')
    BEGIN
        SET @Message = 'AccountType must be Savings, Current, or Fixed Deposit.';
        INSERT INTO AuditSchema.AuditLog (TableName, ColumnName, RecordID, ChangedBy, ActionType, Activity)
        VALUES ('Account', NULL, CONVERT(NVARCHAR(50), @AccountID), @Who, 'REJECTED', @Message);
        RETURN;
    END

    IF @AccountID IS NULL
    BEGIN
-- CREATE path.
        IF @CustomerID IS NULL
        BEGIN
            SET @Message = 'CustomerID is required to open a new account.';
            INSERT INTO AuditSchema.AuditLog (TableName, ColumnName, RecordID, ChangedBy, ActionType, Activity)
            VALUES ('Account', NULL, NULL, @Who, 'REJECTED', @Message);
            RETURN;
        END

        DECLARE @CustomerIsActive BIT;
        SELECT @CustomerIsActive = IsActive FROM dbo.Customer WHERE CustomerID = @CustomerID;

        IF @CustomerIsActive IS NULL
        BEGIN
            SET @Message = 'No customer record found with that CustomerID.';
            INSERT INTO AuditSchema.AuditLog (TableName, ColumnName, RecordID, ChangedBy, ActionType, Activity)
            VALUES ('Account', NULL, NULL, @Who, 'REJECTED', @Message);
            RETURN;
        END

        IF @CustomerIsActive = 0
        BEGIN
            SET @Message = 'Cannot open an account for an inactive customer.';
            INSERT INTO AuditSchema.AuditLog (TableName, ColumnName, RecordID, ChangedBy, ActionType, Activity)
            VALUES ('Account', NULL, NULL, @Who, 'REJECTED', @Message);
            RETURN;
        END

        INSERT INTO dbo.Account (CustomerID, AccountType, Balance, IsActive)
        VALUES (@CustomerID, @AccountType, 0.00, @IsActive);

        SET @Success = 1;
        SET @Message = 'Account opened successfully with a starting balance of RM0.00. Use sp_ProcessTransaction to fund it.';
    END
    ELSE
    BEGIN
-- UPDATE path.
        DECLARE @CurrentBalance DECIMAL(15,2);
        SELECT @CurrentBalance = Balance FROM dbo.Account WHERE AccountID = @AccountID;

        IF @CurrentBalance IS NULL
        BEGIN
            SET @Message = 'No account record found with that AccountID.';
            INSERT INTO AuditSchema.AuditLog (TableName, ColumnName, RecordID, ChangedBy, ActionType, Activity)
            VALUES ('Account', NULL, CONVERT(NVARCHAR(50), @AccountID), @Who, 'REJECTED', @Message);
            RETURN;
        END

-- Refuses to close an account that still holds a non-zero balance. Integrity.
        IF @IsActive = 0 AND @CurrentBalance <> 0
        BEGIN
            SET @Message = 'Cannot close an account with a non-zero balance. Withdraw or transfer the remaining funds first.';
            INSERT INTO AuditSchema.AuditLog (TableName, ColumnName, RecordID, ChangedBy, ActionType, Activity)
            VALUES ('Account', NULL, CONVERT(NVARCHAR(50), @AccountID), @Who, 'REJECTED', @Message);
            RETURN;
        END

        UPDATE dbo.Account
        SET AccountType = @AccountType,
            IsActive     = @IsActive
-- CustomerID and Balance are intentionally excluded from the UPDATE -- ownership reassignment and balance changes both need their own dedicated path. Integrity.
        WHERE AccountID = @AccountID;

        SET @Success = 1;
        SET @Message = 'Account updated successfully.';
    END
END;
GO

-- Layer 1 -- only Bank_Officer can call this at all. Integrity.
GRANT EXECUTE ON dbo.sp_ManageAccount TO Bank_Officer;
GO


-- sp_UpdateOwnStaffRecord: any staff updates their OWN phone only (no @StaffID parameter, so nobody can target someone else's row). Integrity.
CREATE OR ALTER PROCEDURE dbo.sp_UpdateOwnStaffRecord
    @Phone      NVARCHAR(20),
    @Success    BIT OUTPUT,
    @Message    NVARCHAR(200) OUTPUT
WITH EXECUTE AS OWNER
AS
BEGIN
    SET NOCOUNT ON;
    SET @Success = 0;
    DECLARE @Who NVARCHAR(150) = dbo.fn_GetSessionUsername();
    DECLARE @CallerStaffID INT = TRY_CAST(SESSION_CONTEXT(N'StaffID') AS INT);

    IF @CallerStaffID IS NULL
    BEGIN
        SET @Message = 'You must be logged in as a staff member to use this.';
        INSERT INTO AuditSchema.AuditLog (TableName, ColumnName, RecordID, ChangedBy, ActionType, Activity)
        VALUES ('Staff', NULL, NULL, @Who, 'REJECTED', @Message);
        RETURN;
    END

    IF @Phone IS NULL OR LTRIM(RTRIM(@Phone)) = ''
    BEGIN
        SET @Message = 'Phone is required.';
        INSERT INTO AuditSchema.AuditLog (TableName, ColumnName, RecordID, ChangedBy, ActionType, Activity)
        VALUES ('Staff', NULL, CONVERT(NVARCHAR(50), @CallerStaffID), @Who, 'REJECTED', @Message);
        RETURN;
    END

    UPDATE dbo.Staff
    SET Phone = @Phone
    WHERE StaffID = @CallerStaffID;

    SET @Success = 1;
    SET @Message = 'Your contact number has been updated.';
END;
GO

-- Granted to DBA/Manager/Officer -- 'each staff' includes DBA, scoped to one column of their own row only. Confidentiality + Integrity.
GRANT EXECUTE ON dbo.sp_UpdateOwnStaffRecord TO DBA, Bank_Manager, Bank_Officer;
GO


-- sp_ProcessTransaction: Customer deposits/withdraws/transfers on their OWN accounts; amounts over RM10,000 route to approval (team's own extension, not a rubric requirement). Integrity.
CREATE OR ALTER PROCEDURE dbo.sp_ProcessTransaction
    @AccountID        INT,
    @TransactionType  NVARCHAR(20),
    @Amount           DECIMAL(15,2),
    @ToAccountID      INT           = NULL,
    @Success          BIT OUTPUT,
    @Message          NVARCHAR(200) OUTPUT
WITH EXECUTE AS OWNER
AS
BEGIN
    SET NOCOUNT ON;
    SET @Success = 0;
    DECLARE @Who NVARCHAR(150) = dbo.fn_GetSessionUsername();
    DECLARE @CallerCustomerID INT = TRY_CAST(SESSION_CONTEXT(N'CustomerID') AS INT);
    DECLARE @ApprovalThreshold DECIMAL(15,2) = 10000.00;

-- Silently clears ToAccountID for non-Transfer types instead of hitting a raw constraint error.
    IF @TransactionType <> 'Transfer'
        SET @ToAccountID = NULL;

-- Caller must be a logged-in customer.
    IF @CallerCustomerID IS NULL
    BEGIN
        SET @Message = 'You must be logged in as a customer to perform transactions.';
        INSERT INTO AuditSchema.AuditLog (TableName, ColumnName, RecordID, ChangedBy, ActionType, Activity)
        VALUES ('TransactionRecord', NULL, CONVERT(NVARCHAR(50), @AccountID), @Who, 'REJECTED', @Message);
        RETURN;
    END

-- Basic input validation.
    IF @TransactionType IS NULL OR @TransactionType NOT IN ('Deposit', 'Withdrawal', 'Transfer')
    BEGIN
        SET @Message = 'TransactionType must be Deposit, Withdrawal, or Transfer.';
        INSERT INTO AuditSchema.AuditLog (TableName, ColumnName, RecordID, ChangedBy, ActionType, Activity)
        VALUES ('TransactionRecord', NULL, CONVERT(NVARCHAR(50), @AccountID), @Who, 'REJECTED', @Message);
        RETURN;
    END

    IF @Amount IS NULL OR @Amount <= 0
    BEGIN
        SET @Message = 'Amount must be greater than zero.';
        INSERT INTO AuditSchema.AuditLog (TableName, ColumnName, RecordID, ChangedBy, ActionType, Activity)
        VALUES ('TransactionRecord', NULL, CONVERT(NVARCHAR(50), @AccountID), @Who, 'REJECTED', @Message);
        RETURN;
    END

-- Confirms the source account actually belongs to the calling customer -- the real Integrity boundary for writes. Integrity.
    DECLARE @AccountOwnerID INT, @AccountActive BIT, @CurrentBalance DECIMAL(15,2);
    SELECT @AccountOwnerID = CustomerID, @AccountActive = IsActive, @CurrentBalance = Balance
    FROM dbo.Account WHERE AccountID = @AccountID;

    IF @AccountOwnerID IS NULL
    BEGIN
        SET @Message = 'No account found with that AccountID.';
        INSERT INTO AuditSchema.AuditLog (TableName, ColumnName, RecordID, ChangedBy, ActionType, Activity)
        VALUES ('TransactionRecord', NULL, CONVERT(NVARCHAR(50), @AccountID), @Who, 'REJECTED', @Message);
        RETURN;
    END

    IF @AccountOwnerID <> @CallerCustomerID
    BEGIN
        SET @Message = 'You can only perform transactions on your own accounts.';
        INSERT INTO AuditSchema.AuditLog (TableName, ColumnName, RecordID, ChangedBy, ActionType, Activity)
        VALUES ('TransactionRecord', NULL, CONVERT(NVARCHAR(50), @AccountID), @Who, 'REJECTED', @Message);
        RETURN;
    END

    IF @AccountActive = 0
    BEGIN
        SET @Message = 'This account is inactive and cannot be used for transactions.';
        INSERT INTO AuditSchema.AuditLog (TableName, ColumnName, RecordID, ChangedBy, ActionType, Activity)
        VALUES ('TransactionRecord', NULL, CONVERT(NVARCHAR(50), @AccountID), @Who, 'REJECTED', @Message);
        RETURN;
    END

-- Transfer-specific validation.
    IF @TransactionType = 'Transfer'
    BEGIN
        IF @ToAccountID IS NULL
        BEGIN
            SET @Message = 'ToAccountID is required for a transfer.';
            INSERT INTO AuditSchema.AuditLog (TableName, ColumnName, RecordID, ChangedBy, ActionType, Activity)
            VALUES ('TransactionRecord', NULL, CONVERT(NVARCHAR(50), @AccountID), @Who, 'REJECTED', @Message);
            RETURN;
        END

        IF @ToAccountID = @AccountID
        BEGIN
            SET @Message = 'Cannot transfer to the same account.';
            INSERT INTO AuditSchema.AuditLog (TableName, ColumnName, RecordID, ChangedBy, ActionType, Activity)
            VALUES ('TransactionRecord', NULL, CONVERT(NVARCHAR(50), @AccountID), @Who, 'REJECTED', @Message);
            RETURN;
        END

        DECLARE @ToAccountActive BIT;
        SELECT @ToAccountActive = IsActive FROM dbo.Account WHERE AccountID = @ToAccountID;

        IF @ToAccountActive IS NULL
        BEGIN
            SET @Message = 'No destination account found with that ToAccountID.';
            INSERT INTO AuditSchema.AuditLog (TableName, ColumnName, RecordID, ChangedBy, ActionType, Activity)
            VALUES ('TransactionRecord', NULL, CONVERT(NVARCHAR(50), @AccountID), @Who, 'REJECTED', @Message);
            RETURN;
        END

        IF @ToAccountActive = 0
        BEGIN
            SET @Message = 'The destination account is inactive.';
            INSERT INTO AuditSchema.AuditLog (TableName, ColumnName, RecordID, ChangedBy, ActionType, Activity)
            VALUES ('TransactionRecord', NULL, CONVERT(NVARCHAR(50), @AccountID), @Who, 'REJECTED', @Message);
            RETURN;
        END
    END

-- Checks sufficient funds before checking the approval threshold. Integrity.
    IF @TransactionType IN ('Withdrawal', 'Transfer') AND @CurrentBalance < @Amount
    BEGIN
        SET @Message = 'Insufficient balance for this transaction.';
        INSERT INTO AuditSchema.AuditLog (TableName, ColumnName, RecordID, ChangedBy, ActionType, Activity)
        VALUES ('TransactionRecord', NULL, CONVERT(NVARCHAR(50), @AccountID), @Who, 'REJECTED', @Message);
        RETURN;
    END

-- Routes amounts over RM10,000 to PendingApproval instead of posting directly.
    IF @Amount > @ApprovalThreshold
    BEGIN
        DECLARE @CallerUsername NVARCHAR(50);
        SELECT @CallerUsername = Username FROM dbo.UserLogin WHERE CustomerID = @CallerCustomerID;

        INSERT INTO dbo.PendingApproval (AccountID, RequestedBy, Amount, TransactionType, ToAccountID, Status)
        VALUES (@AccountID, @CallerUsername, @Amount, @TransactionType, @ToAccountID, 'Pending');

        SET @Success = 1;
        SET @Message = 'Transaction exceeds RM10,000 and requires Manager approval. Submitted for review.';
        RETURN;
    END

-- Executes the Deposit/Withdrawal/Transfer, wrapped in a transaction for atomicity. Integrity.
    BEGIN TRY
        BEGIN TRANSACTION;

        IF @TransactionType = 'Deposit'
        BEGIN
            UPDATE dbo.Account SET Balance = Balance + @Amount WHERE AccountID = @AccountID;
        END
        ELSE IF @TransactionType = 'Withdrawal'
        BEGIN
            UPDATE dbo.Account SET Balance = Balance - @Amount WHERE AccountID = @AccountID;
        END
        ELSE IF @TransactionType = 'Transfer'
        BEGIN
            UPDATE dbo.Account SET Balance = Balance - @Amount WHERE AccountID = @AccountID;
            UPDATE dbo.Account SET Balance = Balance + @Amount WHERE AccountID = @ToAccountID;
        END

        INSERT INTO dbo.TransactionRecord (AccountID, Amount, TransactionType, ToAccountID)
        VALUES (@AccountID, @Amount, @TransactionType, @ToAccountID);

        COMMIT TRANSACTION;

        SET @Success = 1;
        SET @Message = CONCAT(@TransactionType, ' completed successfully.');
    END TRY
    BEGIN CATCH
        IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION;
        SET @Message = CONCAT('Transaction failed: ', ERROR_MESSAGE());
        INSERT INTO AuditSchema.AuditLog (TableName, ColumnName, RecordID, ChangedBy, ActionType, Activity)
        VALUES ('TransactionRecord', NULL, CONVERT(NVARCHAR(50), @AccountID), @Who, 'REJECTED', @Message);
    END CATCH
END;
GO

-- Layer 1 -- Customer only. Integrity.
GRANT EXECUTE ON dbo.sp_ProcessTransaction TO Customer;
GO


-- sp_ApproveTransaction: Manager approves/rejects a pending request, re-validating funds/status before moving money. Integrity.
CREATE OR ALTER PROCEDURE dbo.sp_ApproveTransaction
    @RequestID  INT,
    @Approve    BIT,           -- 1 = approve and execute, 0 = reject
    @Success    BIT OUTPUT,
    @Message    NVARCHAR(200) OUTPUT
WITH EXECUTE AS OWNER
AS
BEGIN
    SET NOCOUNT ON;
    SET @Success = 0;
    DECLARE @Who NVARCHAR(150) = dbo.fn_GetSessionUsername();
    DECLARE @CallerStaffID INT = TRY_CAST(SESSION_CONTEXT(N'StaffID') AS INT);

    IF @CallerStaffID IS NULL
    BEGIN
        SET @Message = 'You must be logged in as a staff member to use this.';
        INSERT INTO AuditSchema.AuditLog (TableName, ColumnName, RecordID, ChangedBy, ActionType, Activity)
        VALUES ('PendingApproval', NULL, CONVERT(NVARCHAR(50), @RequestID), @Who, 'REJECTED', @Message);
        RETURN;
    END

-- Rejects a NULL @Approve outright -- too consequential to silently treat as 'approve'. Integrity.
    IF @Approve IS NULL
    BEGIN
        SET @Message = 'Approve must be explicitly 1 (approve) or 0 (reject).';
        INSERT INTO AuditSchema.AuditLog (TableName, ColumnName, RecordID, ChangedBy, ActionType, Activity)
        VALUES ('PendingApproval', NULL, CONVERT(NVARCHAR(50), @RequestID), @Who, 'REJECTED', @Message);
        RETURN;
    END

    DECLARE @ApproverUsername NVARCHAR(50);
    SELECT @ApproverUsername = Username FROM dbo.UserLogin WHERE StaffID = @CallerStaffID;

-- Looks up the pending request.
    DECLARE @ReqAccountID INT, @ReqAmount DECIMAL(15,2), @ReqType NVARCHAR(20),
            @ReqToAccountID INT, @ReqStatus NVARCHAR(10);
    SELECT @ReqAccountID = AccountID, @ReqAmount = Amount, @ReqType = TransactionType,
           @ReqToAccountID = ToAccountID, @ReqStatus = Status
    FROM dbo.PendingApproval WHERE RequestID = @RequestID;

    IF @ReqAccountID IS NULL
    BEGIN
        SET @Message = 'No pending request found with that RequestID.';
        INSERT INTO AuditSchema.AuditLog (TableName, ColumnName, RecordID, ChangedBy, ActionType, Activity)
        VALUES ('PendingApproval', NULL, CONVERT(NVARCHAR(50), @RequestID), @Who, 'REJECTED', @Message);
        RETURN;
    END

    IF @ReqStatus <> 'Pending'
    BEGIN
        SET @Message = CONCAT('This request has already been ', @ReqStatus, ' and cannot be actioned again.');
        INSERT INTO AuditSchema.AuditLog (TableName, ColumnName, RecordID, ChangedBy, ActionType, Activity)
        VALUES ('PendingApproval', NULL, CONVERT(NVARCHAR(50), @RequestID), @Who, 'REJECTED', @Message);
        RETURN;
    END

-- Reject path: closes the request, no money moves. Integrity.
    IF @Approve = 0
    BEGIN
        UPDATE dbo.PendingApproval
        SET Status = 'Rejected', ApprovedBy = @ApproverUsername, ApprovalDate = SYSDATETIME()
        WHERE RequestID = @RequestID;

        SET @Success = 1;
        SET @Message = 'Transaction request rejected.';
        RETURN;
    END

-- Approve path -- re-validates before moving money. Integrity.
    DECLARE @CurrentSourceBalance DECIMAL(15,2), @SourceActive BIT;
    SELECT @CurrentSourceBalance = Balance, @SourceActive = IsActive FROM dbo.Account WHERE AccountID = @ReqAccountID;

    IF @SourceActive = 0
    BEGIN
        SET @Message = 'Cannot approve -- the source account has since become inactive. Request left Pending.';
        INSERT INTO AuditSchema.AuditLog (TableName, ColumnName, RecordID, ChangedBy, ActionType, Activity)
        VALUES ('PendingApproval', NULL, CONVERT(NVARCHAR(50), @RequestID), @Who, 'REJECTED', @Message);
        RETURN;
    END

    IF @ReqType IN ('Withdrawal', 'Transfer') AND @CurrentSourceBalance < @ReqAmount
    BEGIN
        SET @Message = 'Cannot approve -- insufficient balance now available on the source account. Request left Pending.';
        INSERT INTO AuditSchema.AuditLog (TableName, ColumnName, RecordID, ChangedBy, ActionType, Activity)
        VALUES ('PendingApproval', NULL, CONVERT(NVARCHAR(50), @RequestID), @Who, 'REJECTED', @Message);
        RETURN;
    END

    IF @ReqType = 'Transfer'
    BEGIN
        DECLARE @DestActive BIT;
        SELECT @DestActive = IsActive FROM dbo.Account WHERE AccountID = @ReqToAccountID;

        IF @DestActive IS NULL OR @DestActive = 0
        BEGIN
            SET @Message = 'Cannot approve -- the destination account is no longer valid. Request left Pending.';
            INSERT INTO AuditSchema.AuditLog (TableName, ColumnName, RecordID, ChangedBy, ActionType, Activity)
            VALUES ('PendingApproval', NULL, CONVERT(NVARCHAR(50), @RequestID), @Who, 'REJECTED', @Message);
            RETURN;
        END
    END

-- Approve path: same Deposit/Withdrawal/Transfer execution as sp_ProcessTransaction, wrapped for atomicity. Integrity.
    BEGIN TRY
        BEGIN TRANSACTION;

        IF @ReqType = 'Deposit'
        BEGIN
            UPDATE dbo.Account SET Balance = Balance + @ReqAmount WHERE AccountID = @ReqAccountID;
        END
        ELSE IF @ReqType = 'Withdrawal'
        BEGIN
            UPDATE dbo.Account SET Balance = Balance - @ReqAmount WHERE AccountID = @ReqAccountID;
        END
        ELSE IF @ReqType = 'Transfer'
        BEGIN
            UPDATE dbo.Account SET Balance = Balance - @ReqAmount WHERE AccountID = @ReqAccountID;
            UPDATE dbo.Account SET Balance = Balance + @ReqAmount WHERE AccountID = @ReqToAccountID;
        END

        INSERT INTO dbo.TransactionRecord (AccountID, Amount, TransactionType, ToAccountID)
        VALUES (@ReqAccountID, @ReqAmount, @ReqType, @ReqToAccountID);

        UPDATE dbo.PendingApproval
        SET Status = 'Approved', ApprovedBy = @ApproverUsername, ApprovalDate = SYSDATETIME()
        WHERE RequestID = @RequestID;

        COMMIT TRANSACTION;

        SET @Success = 1;
        SET @Message = 'Transaction approved and completed successfully.';
    END TRY
    BEGIN CATCH
        IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION;
        SET @Message = CONCAT('Approval failed: ', ERROR_MESSAGE());
        INSERT INTO AuditSchema.AuditLog (TableName, ColumnName, RecordID, ChangedBy, ActionType, Activity)
        VALUES ('PendingApproval', NULL, CONVERT(NVARCHAR(50), @RequestID), @Who, 'REJECTED', @Message);
    END CATCH
END;
GO

-- Granted to Bank_Manager only, matching vw_PendingApprovalAll's read scope. Integrity.
GRANT EXECUTE ON dbo.sp_ApproveTransaction TO Bank_Manager;
GO


-- PART 9: recovery procedures for the 4 temporal tables -- restore a wrongly-changed row, or reinsert a deleted one with its original ID. Availability.

USE SmartBankDB;
GO

-- sp_RecoverStaff. Availability.
CREATE OR ALTER PROCEDURE dbo.sp_RecoverStaff
    @StaffID        INT,
    @AsOfDateTime   DATETIME2,
    @Success        BIT OUTPUT,
    @Message        NVARCHAR(200) OUTPUT
WITH EXECUTE AS OWNER
AS
BEGIN
    SET NOCOUNT ON;
    SET @Success = 0;
    DECLARE @Who NVARCHAR(150) = dbo.fn_GetSessionUsername();
    DECLARE @CallerStaffID INT = TRY_CAST(SESSION_CONTEXT(N'StaffID') AS INT);

    IF @CallerStaffID IS NULL
    BEGIN
        SET @Message = 'You must be logged in to use this.';
        INSERT INTO AuditSchema.AuditLog (TableName, ColumnName, RecordID, ChangedBy, ActionType, Activity)
        VALUES ('Staff', NULL, CONVERT(NVARCHAR(50), @StaffID), @Who, 'REJECTED', @Message);
        RETURN;
    END

    IF @AsOfDateTime IS NULL OR @AsOfDateTime > SYSDATETIME()
    BEGIN
        SET @Message = 'AsOfDateTime must be a valid point in the past.';
        INSERT INTO AuditSchema.AuditLog (TableName, ColumnName, RecordID, ChangedBy, ActionType, Activity)
        VALUES ('Staff', NULL, CONVERT(NVARCHAR(50), @StaffID), @Who, 'REJECTED', @Message);
        RETURN;
    END

    DECLARE @HistStaffName NVARCHAR(100), @HistPosition NVARCHAR(50), @HistBranch NVARCHAR(100),
            @HistPhone NVARCHAR(20), @HistSalary DECIMAL(15,2), @HistIsActive BIT;

    SELECT TOP 1
        @HistStaffName = StaffName, @HistPosition = Position, @HistBranch = Branch,
        @HistPhone = Phone, @HistSalary = Salary, @HistIsActive = IsActive
    FROM dbo.Staff FOR SYSTEM_TIME AS OF @AsOfDateTime
    WHERE StaffID = @StaffID;

    IF @HistStaffName IS NULL
    BEGIN
        SET @Message = 'No historical record found for that StaffID at the given point in time.';
        INSERT INTO AuditSchema.AuditLog (TableName, ColumnName, RecordID, ChangedBy, ActionType, Activity)
        VALUES ('Staff', NULL, CONVERT(NVARCHAR(50), @StaffID), @Who, 'REJECTED', @Message);
        RETURN;
    END

    IF EXISTS (SELECT 1 FROM dbo.Staff WHERE StaffID = @StaffID)
    BEGIN
        -- Scenario A: row exists but was wrongly modified -- roll it back
        UPDATE dbo.Staff
        SET StaffName = @HistStaffName, Position = @HistPosition, Branch = @HistBranch,
            Phone = @HistPhone, Salary = @HistSalary, IsActive = @HistIsActive
        WHERE StaffID = @StaffID;

        SET @Success = 1;
        SET @Message = 'Staff record rolled back to its state as of the specified time.';
    END
    ELSE
    BEGIN
        -- Scenario B: row was deleted -- reinsert with its ORIGINAL StaffID
        SET IDENTITY_INSERT dbo.Staff ON;

        INSERT INTO dbo.Staff (StaffID, StaffName, Position, Branch, Phone, Salary, IsActive)
        VALUES (@StaffID, @HistStaffName, @HistPosition, @HistBranch, @HistPhone, @HistSalary, @HistIsActive);

        SET IDENTITY_INSERT dbo.Staff OFF;

        SET @Success = 1;
        SET @Message = 'Staff record restored (it had been deleted).';
    END
END;
GO

GRANT EXECUTE ON dbo.sp_RecoverStaff TO RecoveryAdmin;
GO


-- sp_RecoverCustomer: restores Customer rows; ICNumber restores as its original encrypted bytes, no re-encryption needed. Confidentiality + Availability.
CREATE OR ALTER PROCEDURE dbo.sp_RecoverCustomer
    @CustomerID     INT,
    @AsOfDateTime   DATETIME2,
    @Success        BIT OUTPUT,
    @Message        NVARCHAR(200) OUTPUT
WITH EXECUTE AS OWNER
AS
BEGIN
    SET NOCOUNT ON;
    SET @Success = 0;
    DECLARE @Who NVARCHAR(150) = dbo.fn_GetSessionUsername();
    DECLARE @CallerStaffID INT = TRY_CAST(SESSION_CONTEXT(N'StaffID') AS INT);

    IF @CallerStaffID IS NULL
    BEGIN
        SET @Message = 'You must be logged in to use this.';
        INSERT INTO AuditSchema.AuditLog (TableName, ColumnName, RecordID, ChangedBy, ActionType, Activity)
        VALUES ('Customer', NULL, CONVERT(NVARCHAR(50), @CustomerID), @Who, 'REJECTED', @Message);
        RETURN;
    END

    IF @AsOfDateTime IS NULL OR @AsOfDateTime > SYSDATETIME()
    BEGIN
        SET @Message = 'AsOfDateTime must be a valid point in the past.';
        INSERT INTO AuditSchema.AuditLog (TableName, ColumnName, RecordID, ChangedBy, ActionType, Activity)
        VALUES ('Customer', NULL, CONVERT(NVARCHAR(50), @CustomerID), @Who, 'REJECTED', @Message);
        RETURN;
    END

    DECLARE @HistCustomerName NVARCHAR(100), @HistICNumber VARBINARY(MAX), @HistICHash VARBINARY(32),
            @HistPhone NVARCHAR(20), @HistAddress NVARCHAR(255), @HistIsActive BIT;

    SELECT TOP 1
        @HistCustomerName = CustomerName, @HistICNumber = ICNumber, @HistICHash = ICNumberHash,
        @HistPhone = Phone, @HistAddress = Address, @HistIsActive = IsActive
    FROM dbo.Customer FOR SYSTEM_TIME AS OF @AsOfDateTime
    WHERE CustomerID = @CustomerID;

    IF @HistCustomerName IS NULL
    BEGIN
        SET @Message = 'No historical record found for that CustomerID at the given point in time.';
        INSERT INTO AuditSchema.AuditLog (TableName, ColumnName, RecordID, ChangedBy, ActionType, Activity)
        VALUES ('Customer', NULL, CONVERT(NVARCHAR(50), @CustomerID), @Who, 'REJECTED', @Message);
        RETURN;
    END

    IF EXISTS (SELECT 1 FROM dbo.Customer WHERE CustomerID = @CustomerID)
    BEGIN
        UPDATE dbo.Customer
        SET CustomerName = @HistCustomerName, ICNumber = @HistICNumber, ICNumberHash = @HistICHash,
            Phone = @HistPhone, Address = @HistAddress, IsActive = @HistIsActive
        WHERE CustomerID = @CustomerID;

        SET @Success = 1;
        SET @Message = 'Customer record rolled back to its state as of the specified time.';
    END
    ELSE
    BEGIN
        SET IDENTITY_INSERT dbo.Customer ON;

        INSERT INTO dbo.Customer (CustomerID, CustomerName, ICNumber, ICNumberHash, Phone, Address, IsActive)
        VALUES (@CustomerID, @HistCustomerName, @HistICNumber, @HistICHash, @HistPhone, @HistAddress, @HistIsActive);

        SET IDENTITY_INSERT dbo.Customer OFF;

        SET @Success = 1;
        SET @Message = 'Customer record restored (it had been deleted).';
    END
END;
GO

GRANT EXECUTE ON dbo.sp_RecoverCustomer TO RecoveryAdmin;
GO


-- sp_RecoverAccount. Availability.
CREATE OR ALTER PROCEDURE dbo.sp_RecoverAccount
    @AccountID      INT,
    @AsOfDateTime   DATETIME2,
    @Success        BIT OUTPUT,
    @Message        NVARCHAR(200) OUTPUT
WITH EXECUTE AS OWNER
AS
BEGIN
    SET NOCOUNT ON;
    SET @Success = 0;
    DECLARE @Who NVARCHAR(150) = dbo.fn_GetSessionUsername();
    DECLARE @CallerStaffID INT = TRY_CAST(SESSION_CONTEXT(N'StaffID') AS INT);

    IF @CallerStaffID IS NULL
    BEGIN
        SET @Message = 'You must be logged in to use this.';
        INSERT INTO AuditSchema.AuditLog (TableName, ColumnName, RecordID, ChangedBy, ActionType, Activity)
        VALUES ('Account', NULL, CONVERT(NVARCHAR(50), @AccountID), @Who, 'REJECTED', @Message);
        RETURN;
    END

    IF @AsOfDateTime IS NULL OR @AsOfDateTime > SYSDATETIME()
    BEGIN
        SET @Message = 'AsOfDateTime must be a valid point in the past.';
        INSERT INTO AuditSchema.AuditLog (TableName, ColumnName, RecordID, ChangedBy, ActionType, Activity)
        VALUES ('Account', NULL, CONVERT(NVARCHAR(50), @AccountID), @Who, 'REJECTED', @Message);
        RETURN;
    END

    DECLARE @HistCustomerID INT, @HistAccountType NVARCHAR(20), @HistBalance DECIMAL(15,2), @HistIsActive BIT;

    SELECT TOP 1
        @HistCustomerID = CustomerID, @HistAccountType = AccountType,
        @HistBalance = Balance, @HistIsActive = IsActive
    FROM dbo.Account FOR SYSTEM_TIME AS OF @AsOfDateTime
    WHERE AccountID = @AccountID;

    IF @HistAccountType IS NULL
    BEGIN
        SET @Message = 'No historical record found for that AccountID at the given point in time.';
        INSERT INTO AuditSchema.AuditLog (TableName, ColumnName, RecordID, ChangedBy, ActionType, Activity)
        VALUES ('Account', NULL, CONVERT(NVARCHAR(50), @AccountID), @Who, 'REJECTED', @Message);
        RETURN;
    END

    IF EXISTS (SELECT 1 FROM dbo.Account WHERE AccountID = @AccountID)
    BEGIN
        UPDATE dbo.Account
        SET CustomerID = @HistCustomerID, AccountType = @HistAccountType,
            Balance = @HistBalance, IsActive = @HistIsActive
        WHERE AccountID = @AccountID;

        SET @Success = 1;
        SET @Message = 'Account record rolled back to its state as of the specified time.';
    END
    ELSE
    BEGIN
        SET IDENTITY_INSERT dbo.Account ON;

        INSERT INTO dbo.Account (AccountID, CustomerID, AccountType, Balance, IsActive)
        VALUES (@AccountID, @HistCustomerID, @HistAccountType, @HistBalance, @HistIsActive);

        SET IDENTITY_INSERT dbo.Account OFF;

        SET @Success = 1;
        SET @Message = 'Account record restored (it had been deleted).';
    END
END;
GO

GRANT EXECUTE ON dbo.sp_RecoverAccount TO RecoveryAdmin;
GO


-- sp_RecoverTransactionRecord: restores TransactionRecord rows; since this table is insert-only in practice, ever needing this implies someone bypassed the app layer. Availability.
CREATE OR ALTER PROCEDURE dbo.sp_RecoverTransactionRecord
    @TransID        INT,
    @AsOfDateTime   DATETIME2,
    @Success        BIT OUTPUT,
    @Message        NVARCHAR(200) OUTPUT
WITH EXECUTE AS OWNER
AS
BEGIN
    SET NOCOUNT ON;
    SET @Success = 0;
    DECLARE @Who NVARCHAR(150) = dbo.fn_GetSessionUsername();
    DECLARE @CallerStaffID INT = TRY_CAST(SESSION_CONTEXT(N'StaffID') AS INT);

    IF @CallerStaffID IS NULL
    BEGIN
        SET @Message = 'You must be logged in to use this.';
        INSERT INTO AuditSchema.AuditLog (TableName, ColumnName, RecordID, ChangedBy, ActionType, Activity)
        VALUES ('TransactionRecord', NULL, CONVERT(NVARCHAR(50), @TransID), @Who, 'REJECTED', @Message);
        RETURN;
    END

    IF @AsOfDateTime IS NULL OR @AsOfDateTime > SYSDATETIME()
    BEGIN
        SET @Message = 'AsOfDateTime must be a valid point in the past.';
        INSERT INTO AuditSchema.AuditLog (TableName, ColumnName, RecordID, ChangedBy, ActionType, Activity)
        VALUES ('TransactionRecord', NULL, CONVERT(NVARCHAR(50), @TransID), @Who, 'REJECTED', @Message);
        RETURN;
    END

    DECLARE @HistAccountID INT, @HistTransDate DATETIME2, @HistAmount DECIMAL(15,2),
            @HistTransactionType NVARCHAR(20), @HistToAccountID INT;

    SELECT TOP 1
        @HistAccountID = AccountID, @HistTransDate = TransDate, @HistAmount = Amount,
        @HistTransactionType = TransactionType, @HistToAccountID = ToAccountID
    FROM dbo.TransactionRecord FOR SYSTEM_TIME AS OF @AsOfDateTime
    WHERE TransID = @TransID;

    IF @HistTransactionType IS NULL
    BEGIN
        SET @Message = 'No historical record found for that TransID at the given point in time.';
        INSERT INTO AuditSchema.AuditLog (TableName, ColumnName, RecordID, ChangedBy, ActionType, Activity)
        VALUES ('TransactionRecord', NULL, CONVERT(NVARCHAR(50), @TransID), @Who, 'REJECTED', @Message);
        RETURN;
    END

    IF EXISTS (SELECT 1 FROM dbo.TransactionRecord WHERE TransID = @TransID)
    BEGIN
        UPDATE dbo.TransactionRecord
        SET AccountID = @HistAccountID, TransDate = @HistTransDate, Amount = @HistAmount,
            TransactionType = @HistTransactionType, ToAccountID = @HistToAccountID
        WHERE TransID = @TransID;

        SET @Success = 1;
        SET @Message = 'TransactionRecord rolled back to its state as of the specified time.';
    END
    ELSE
    BEGIN
        SET IDENTITY_INSERT dbo.TransactionRecord ON;

        INSERT INTO dbo.TransactionRecord (TransID, AccountID, TransDate, Amount, TransactionType, ToAccountID)
        VALUES (@TransID, @HistAccountID, @HistTransDate, @HistAmount, @HistTransactionType, @HistToAccountID);

        SET IDENTITY_INSERT dbo.TransactionRecord OFF;

        SET @Success = 1;
        SET @Message = 'TransactionRecord restored (it had been deleted).';
    END
END;
GO

GRANT EXECUTE ON dbo.sp_RecoverTransactionRecord TO RecoveryAdmin;
GO


-- PART 10: automated Full/Differential/Log backups (6h/1h/5min); RPO = 5 minutes, tied to the Log interval; every backup encrypted. Availability.

USE master;
GO

-- [B1] Certificate encrypting every backup -- closes the 'unprotected backups' gap TDE alone didn't cover. Availability.
IF NOT EXISTS (SELECT 1 FROM sys.symmetric_keys WHERE name = '##MS_DatabaseMasterKey##')
    CREATE MASTER KEY ENCRYPTION BY PASSWORD = 'SmartBank_MasterDMK_P@ss2026!';
GO

IF NOT EXISTS (SELECT 1 FROM sys.certificates WHERE name = 'BackupEncryptCert')
    CREATE CERTIFICATE BackupEncryptCert
        WITH SUBJECT = 'Certificate for SmartBankDB backup encryption';
GO

-- [B2] Switches to FULL recovery model so transaction log backups are meaningful. Availability.
ALTER DATABASE SmartBankDB SET RECOVERY FULL;
GO

-- [B3] sp_PerformFullBackup / sp_PerformDifferentialBackup / sp_PerformLogBackup: build a timestamped filename and run the encrypted backup. Availability.
USE SmartBankDB;
GO

CREATE OR ALTER PROCEDURE dbo.sp_PerformFullBackup
AS
BEGIN
    SET NOCOUNT ON;
    DECLARE @FileName NVARCHAR(260);
    DECLARE @Timestamp NVARCHAR(20) = FORMAT(SYSDATETIME(), 'yyyyMMdd_HHmmss');
    SET @FileName = 'C:\SQLBackups\Full\SmartBankDB_Full_' + @Timestamp + '.bak';

    DECLARE @SQL NVARCHAR(MAX) = N'
        BACKUP DATABASE SmartBankDB
        TO DISK = ''' + @FileName + N'''
        WITH INIT, COMPRESSION,
        ENCRYPTION (ALGORITHM = AES_256, SERVER CERTIFICATE = BackupEncryptCert),
        NAME = ''SmartBankDB-Full Backup'';';

    EXEC sp_executesql @SQL;
END;
GO

CREATE OR ALTER PROCEDURE dbo.sp_PerformDifferentialBackup
AS
BEGIN
    SET NOCOUNT ON;
    DECLARE @FileName NVARCHAR(260);
    DECLARE @Timestamp NVARCHAR(20) = FORMAT(SYSDATETIME(), 'yyyyMMdd_HHmmss');
    SET @FileName = 'C:\SQLBackups\Differential\SmartBankDB_Diff_' + @Timestamp + '.bak';

    DECLARE @SQL NVARCHAR(MAX) = N'
        BACKUP DATABASE SmartBankDB
        TO DISK = ''' + @FileName + N'''
        WITH DIFFERENTIAL, INIT, COMPRESSION,
        ENCRYPTION (ALGORITHM = AES_256, SERVER CERTIFICATE = BackupEncryptCert),
        NAME = ''SmartBankDB-Differential Backup'';';

    EXEC sp_executesql @SQL;
END;
GO

CREATE OR ALTER PROCEDURE dbo.sp_PerformLogBackup
AS
BEGIN
    SET NOCOUNT ON;
    DECLARE @FileName NVARCHAR(260);
    DECLARE @Timestamp NVARCHAR(20) = FORMAT(SYSDATETIME(), 'yyyyMMdd_HHmmss');
    SET @FileName = 'C:\SQLBackups\Log\SmartBankDB_Log_' + @Timestamp + '.trn';

    DECLARE @SQL NVARCHAR(MAX) = N'
        BACKUP LOG SmartBankDB
        TO DISK = ''' + @FileName + N'''
        WITH INIT, COMPRESSION,
        ENCRYPTION (ALGORITHM = AES_256, SERVER CERTIFICATE = BackupEncryptCert),
        NAME = ''SmartBankDB-Log Backup'';';

    EXEC sp_executesql @SQL;
END;
GO

-- [B4] Runs one Full backup immediately to start the log chain. Availability.
EXEC dbo.sp_PerformFullBackup;
GO

PRINT 'B4 -- initial Full backup complete, log chain started.';
GO


-- [B5] SQL Server Agent Jobs -- the actual 'automated' part; schedules the 3 backup procs to run on their own. Availability.
USE msdb;
GO

-- ---------- Full backup: every 6 hours ----------
IF NOT EXISTS (SELECT 1 FROM msdb.dbo.sysjobs WHERE name = N'SmartBankDB - Full Backup')
BEGIN
    EXEC msdb.dbo.sp_add_job
        @job_name = N'SmartBankDB - Full Backup',
        @enabled = 1,
        @description = N'Automated Full backup for SmartBankDB (Availability Section 3, Requirement 3).';

    EXEC msdb.dbo.sp_add_jobstep
        @job_name = N'SmartBankDB - Full Backup',
        @step_name = N'Run Full Backup',
        @subsystem = N'TSQL',
        @command = N'EXEC SmartBankDB.dbo.sp_PerformFullBackup;',
        @database_name = N'SmartBankDB';

    EXEC msdb.dbo.sp_add_schedule
        @schedule_name = N'SmartBankDB - Every 6 Hours',
        @freq_type = 4,             -- daily
        @freq_interval = 1,         -- every 1 day
        @freq_subday_type = 8,      -- hours
        @freq_subday_interval = 6,  -- every 6 hours
        @active_start_time = 000000,
        @active_end_time = 235959;

    EXEC msdb.dbo.sp_attach_schedule
        @job_name = N'SmartBankDB - Full Backup',
        @schedule_name = N'SmartBankDB - Every 6 Hours';

    EXEC msdb.dbo.sp_add_jobserver
        @job_name = N'SmartBankDB - Full Backup',
        @server_name = N'(local)';
END
GO

-- ---------- Differential backup: every 1 hour ----------
IF NOT EXISTS (SELECT 1 FROM msdb.dbo.sysjobs WHERE name = N'SmartBankDB - Differential Backup')
BEGIN
    EXEC msdb.dbo.sp_add_job
        @job_name = N'SmartBankDB - Differential Backup',
        @enabled = 1,
        @description = N'Automated Differential backup for SmartBankDB (Availability Section 3, Requirement 3).';

    EXEC msdb.dbo.sp_add_jobstep
        @job_name = N'SmartBankDB - Differential Backup',
        @step_name = N'Run Differential Backup',
        @subsystem = N'TSQL',
        @command = N'EXEC SmartBankDB.dbo.sp_PerformDifferentialBackup;',
        @database_name = N'SmartBankDB';

    EXEC msdb.dbo.sp_add_schedule
        @schedule_name = N'SmartBankDB - Every 1 Hour',
        @freq_type = 4,
        @freq_interval = 1,
        @freq_subday_type = 8,
        @freq_subday_interval = 1,
        @active_start_time = 000000,
        @active_end_time = 235959;

    EXEC msdb.dbo.sp_attach_schedule
        @job_name = N'SmartBankDB - Differential Backup',
        @schedule_name = N'SmartBankDB - Every 1 Hour';

    EXEC msdb.dbo.sp_add_jobserver
        @job_name = N'SmartBankDB - Differential Backup',
        @server_name = N'(local)';
END
GO

-- ---------- Transaction log backup: every 5 minutes (= RPO) ----------
IF NOT EXISTS (SELECT 1 FROM msdb.dbo.sysjobs WHERE name = N'SmartBankDB - Log Backup')
BEGIN
    EXEC msdb.dbo.sp_add_job
        @job_name = N'SmartBankDB - Log Backup',
        @enabled = 1,
        @description = N'Automated Transaction Log backup for SmartBankDB -- delivers the 5-minute RPO (Availability Section 3, Requirements 2 & 3).';

    EXEC msdb.dbo.sp_add_jobstep
        @job_name = N'SmartBankDB - Log Backup',
        @step_name = N'Run Log Backup',
        @subsystem = N'TSQL',
        @command = N'EXEC SmartBankDB.dbo.sp_PerformLogBackup;',
        @database_name = N'SmartBankDB';

    EXEC msdb.dbo.sp_add_schedule
        @schedule_name = N'SmartBankDB - Every 5 Minutes',
        @freq_type = 4,
        @freq_interval = 1,
        @freq_subday_type = 4,      -- minutes
        @freq_subday_interval = 5,  -- every 5 minutes
        @active_start_time = 000000,
        @active_end_time = 235959;

    EXEC msdb.dbo.sp_attach_schedule
        @job_name = N'SmartBankDB - Log Backup',
        @schedule_name = N'SmartBankDB - Every 5 Minutes';

    EXEC msdb.dbo.sp_add_jobserver
        @job_name = N'SmartBankDB - Log Backup',
        @server_name = N'(local)';
END
GO

USE master;
GO

-- [B6] Backs up the backup-encryption certificate itself -- losing it makes every encrypted backup permanently unreadable. Availability. (Runs against master, where BackupEncryptCert actually lives -- BACKUP CERTIFICATE looks it up in whichever database is currently active, unlike BACKUP DATABASE's ENCRYPTION clause.)
BACKUP CERTIFICATE BackupEncryptCert
    TO FILE = 'C:\SQLKeys\BackupEncryptCert.cer'
    WITH PRIVATE KEY (
        FILE = 'C:\SQLKeys\BackupEncryptCert.pvk',
        ENCRYPTION BY PASSWORD = 'SmartBank_KeyBackup_P@ss2026!'
    );
GO

PRINT 'Part 10 (Backup Automation) setup complete -- 3 jobs registered: Full (6h), Differential (1h), Log (5min).';
GO


-- =====================================================================================
-- PART 11: automatic session-context initialisation via server-level logon trigger.
-- Confidentiality (RLS support).
--
-- Fires the instant one of our per-person native logins (SmartBank_Manager1/2, DBA1/2,
-- Officer1/2, Customer1/2) connects, looks the person up in dbo.UserLogin, and populates
-- SESSION_CONTEXT with UserType + StaffID/CustomerID exactly as sp_Login would have.
--
-- Effect: after connecting via SQL Server Authentication, the person can query the RLS
-- 'Own' views directly (e.g. SELECT * FROM dbo.vw_StaffOwnRecord) and see the correct
-- row -- no sp_Login call needed. Existing views + procs are UNCHANGED and still read
-- SESSION_CONTEXT the same way; only how it gets populated has moved from an explicit
-- call to an automatic trigger.
--
-- Runs WITH EXECUTE AS 'sa' because logon triggers execute BEFORE the connection's
-- normal permissions apply -- 'sa' is the standard high-privileged identity for
-- server-scoped triggers that need to read from a specific database.
--
-- Whole body is wrapped in TRY/CATCH so any unexpected error inside the trigger
-- silently returns rather than blocking the login -- protects against lockout.
-- =====================================================================================
USE master;
GO

CREATE OR ALTER TRIGGER trg_AutoSetSessionContext
ON ALL SERVER WITH EXECUTE AS 'sa'
FOR LOGON
AS
BEGIN
    BEGIN TRY
        DECLARE @LoginName SYSNAME = ORIGINAL_LOGIN();

        -- Only act on our specific test logins -- ignore every other connection.
        IF @LoginName NOT IN ('SmartBank_Manager1', 'SmartBank_Manager2',
                              'SmartBank_DBA1',     'SmartBank_DBA2',
                              'SmartBank_Officer1', 'SmartBank_Officer2',
                              'SmartBank_Customer1','SmartBank_Customer2')
            RETURN;

        -- Skip if SmartBankDB isn't reachable (mid-restore, offline, missing)
        -- -- prevents the trigger from throwing during install/restore scenarios.
        IF DB_ID('SmartBankDB') IS NULL
           OR (SELECT state_desc FROM sys.databases WHERE name = 'SmartBankDB') <> N'ONLINE'
            RETURN;

        DECLARE @UserType NVARCHAR(20), @StaffID INT, @CustomerID INT;

        SELECT @UserType   = UserType,
               @StaffID    = StaffID,
               @CustomerID = CustomerID
        FROM SmartBankDB.dbo.UserLogin
        WHERE Username = @LoginName
          AND IsActive = 1;

        IF @UserType IS NOT NULL
        BEGIN
            EXEC sp_set_session_context @key = N'UserType',   @value = @UserType,   @read_only = 1;
            IF @StaffID    IS NOT NULL
                EXEC sp_set_session_context @key = N'StaffID',    @value = @StaffID,    @read_only = 1;
            IF @CustomerID IS NOT NULL
                EXEC sp_set_session_context @key = N'CustomerID', @value = @CustomerID, @read_only = 1;
        END
    END TRY
    BEGIN CATCH
        -- Silently continue -- never block a login due to trigger error.
        RETURN;
    END CATCH
END;
GO

PRINT 'Part 11 (Auto Session Context) setup complete -- native SQL logins for test identities can now query RLS views directly.';
GO


-- =====================================================================================
-- PART 12: seed the 8 test identities into dbo.Staff / dbo.Customer / dbo.Account /
-- dbo.UserLogin so the logon trigger (Part 11) has something to look up.
-- Confidentiality (identity binding) + demo enablement.
--
-- Rows created:
--   Staff:      Aiman Zulkifli    (Manager1), Rashid Karim    (Manager2),
--               Nabil Hakim       (DBA1),     Zainab Ismail   (DBA2),
--               Farah Aina        (Officer1), Ahmad Faizal    (Officer2)
--   Customer:   Wei Ming Tan      (Customer1), Siti Nurhaliza (Customer2)
--   Account:    one Savings/RM0 per customer
--   UserLogin:  one row per identity, Username matches SmartBank_XxxN native login
--
-- Each identity guarded by IF NOT EXISTS on Username, so re-running is safe -- rows
-- already present are skipped, only missing ones get inserted. Passwords hashed via
-- fn_HashPassword (SHA2_512 + per-user salt) exactly like sp_ManageStaff would.
-- IC numbers encrypted via CLE_ICNumber_SymKey.
-- =====================================================================================
USE SmartBankDB;
GO

DECLARE @Salt VARBINARY(32);

-- ---------- Manager1: Aiman Zulkifli ----------
IF NOT EXISTS (SELECT 1 FROM dbo.UserLogin WHERE Username = 'SmartBank_Manager1')
BEGIN
    INSERT INTO dbo.Staff (StaffName, Position, Branch, Phone, Salary, IsActive)
    VALUES ('Aiman Zulkifli', 'Bank Manager', 'KL Branch', '0111111111', 9000.00, 1);

    SET @Salt = CRYPT_GEN_RANDOM(32);
    INSERT INTO dbo.UserLogin (Username, PasswordHash, Salt, StaffID, UserType, PasswordLastChanged, IsActive)
    VALUES ('SmartBank_Manager1', dbo.fn_HashPassword('Manager1P@ss!', @Salt), @Salt,
            SCOPE_IDENTITY(), 'Staff', SYSDATETIME(), 1);
END

-- ---------- Manager2: Rashid Karim ----------
IF NOT EXISTS (SELECT 1 FROM dbo.UserLogin WHERE Username = 'SmartBank_Manager2')
BEGIN
    INSERT INTO dbo.Staff (StaffName, Position, Branch, Phone, Salary, IsActive)
    VALUES ('Rashid Karim', 'Bank Manager', 'PJ Branch', '0177777777', 9200.00, 1);

    SET @Salt = CRYPT_GEN_RANDOM(32);
    INSERT INTO dbo.UserLogin (Username, PasswordHash, Salt, StaffID, UserType, PasswordLastChanged, IsActive)
    VALUES ('SmartBank_Manager2', dbo.fn_HashPassword('Manager2P@ss!', @Salt), @Salt,
            SCOPE_IDENTITY(), 'Staff', SYSDATETIME(), 1);
END

-- ---------- DBA1: Nabil Hakim ----------
IF NOT EXISTS (SELECT 1 FROM dbo.UserLogin WHERE Username = 'SmartBank_DBA1')
BEGIN
    INSERT INTO dbo.Staff (StaffName, Position, Branch, Phone, Salary, IsActive)
    VALUES ('Nabil Hakim', 'DBA', 'HQ', '0122222222', 8000.00, 1);

    SET @Salt = CRYPT_GEN_RANDOM(32);
    INSERT INTO dbo.UserLogin (Username, PasswordHash, Salt, StaffID, UserType, PasswordLastChanged, IsActive)
    VALUES ('SmartBank_DBA1', dbo.fn_HashPassword('Dba1P@ss!', @Salt), @Salt,
            SCOPE_IDENTITY(), 'Staff', SYSDATETIME(), 1);
END

-- ---------- DBA2: Zainab Ismail ----------
IF NOT EXISTS (SELECT 1 FROM dbo.UserLogin WHERE Username = 'SmartBank_DBA2')
BEGIN
    INSERT INTO dbo.Staff (StaffName, Position, Branch, Phone, Salary, IsActive)
    VALUES ('Zainab Ismail', 'DBA', 'HQ', '0188888888', 8200.00, 1);

    SET @Salt = CRYPT_GEN_RANDOM(32);
    INSERT INTO dbo.UserLogin (Username, PasswordHash, Salt, StaffID, UserType, PasswordLastChanged, IsActive)
    VALUES ('SmartBank_DBA2', dbo.fn_HashPassword('Dba2P@ss!', @Salt), @Salt,
            SCOPE_IDENTITY(), 'Staff', SYSDATETIME(), 1);
END

-- ---------- Officer1: Farah Aina ----------
IF NOT EXISTS (SELECT 1 FROM dbo.UserLogin WHERE Username = 'SmartBank_Officer1')
BEGIN
    INSERT INTO dbo.Staff (StaffName, Position, Branch, Phone, Salary, IsActive)
    VALUES ('Farah Aina', 'Bank Officer', 'KL Branch', '0133333333', 4500.00, 1);

    SET @Salt = CRYPT_GEN_RANDOM(32);
    INSERT INTO dbo.UserLogin (Username, PasswordHash, Salt, StaffID, UserType, PasswordLastChanged, IsActive)
    VALUES ('SmartBank_Officer1', dbo.fn_HashPassword('Officer1P@ss!', @Salt), @Salt,
            SCOPE_IDENTITY(), 'Staff', SYSDATETIME(), 1);
END

-- ---------- Officer2: Ahmad Faizal ----------
IF NOT EXISTS (SELECT 1 FROM dbo.UserLogin WHERE Username = 'SmartBank_Officer2')
BEGIN
    INSERT INTO dbo.Staff (StaffName, Position, Branch, Phone, Salary, IsActive)
    VALUES ('Ahmad Faizal', 'Bank Officer', 'PJ Branch', '0199999999', 4600.00, 1);

    SET @Salt = CRYPT_GEN_RANDOM(32);
    INSERT INTO dbo.UserLogin (Username, PasswordHash, Salt, StaffID, UserType, PasswordLastChanged, IsActive)
    VALUES ('SmartBank_Officer2', dbo.fn_HashPassword('Officer2P@ss!', @Salt), @Salt,
            SCOPE_IDENTITY(), 'Staff', SYSDATETIME(), 1);
END
GO

-- ---------- Customer1 + Customer2 (ICNumber CLE-encrypted) ----------
OPEN SYMMETRIC KEY CLE_ICNumber_SymKey DECRYPTION BY CERTIFICATE CLE_ICNumber_Cert;

DECLARE @Salt VARBINARY(32), @ICNumber NVARCHAR(20), @NewCustomerID INT;

-- Customer1: Wei Ming Tan
IF NOT EXISTS (SELECT 1 FROM dbo.UserLogin WHERE Username = 'SmartBank_Customer1')
BEGIN
    SET @ICNumber = '990101011234';
    INSERT INTO dbo.Customer (CustomerName, ICNumber, ICNumberHash, Phone, Address, IsActive)
    VALUES (
        'Wei Ming Tan',
        EncryptByKey(Key_GUID('CLE_ICNumber_SymKey'), CONVERT(VARBINARY(MAX), @ICNumber)),
        HASHBYTES('SHA2_256', @ICNumber),
        '0141111111', '1 Test Street, KL', 1
    );
    SET @NewCustomerID = SCOPE_IDENTITY();

    INSERT INTO dbo.Account (CustomerID, AccountType, Balance, IsActive)
    VALUES (@NewCustomerID, 'Savings', 0.00, 1);

    SET @Salt = CRYPT_GEN_RANDOM(32);
    INSERT INTO dbo.UserLogin (Username, PasswordHash, Salt, CustomerID, UserType, PasswordLastChanged, IsActive)
    VALUES ('SmartBank_Customer1', dbo.fn_HashPassword('Customer1P@ss!', @Salt), @Salt,
            @NewCustomerID, 'Customer', SYSDATETIME(), 1);
END

-- Customer2: Siti Nurhaliza
IF NOT EXISTS (SELECT 1 FROM dbo.UserLogin WHERE Username = 'SmartBank_Customer2')
BEGIN
    SET @ICNumber = '990202021234';
    INSERT INTO dbo.Customer (CustomerName, ICNumber, ICNumberHash, Phone, Address, IsActive)
    VALUES (
        'Siti Nurhaliza',
        EncryptByKey(Key_GUID('CLE_ICNumber_SymKey'), CONVERT(VARBINARY(MAX), @ICNumber)),
        HASHBYTES('SHA2_256', @ICNumber),
        '0142222222', '2 Test Street, KL', 1
    );
    SET @NewCustomerID = SCOPE_IDENTITY();

    INSERT INTO dbo.Account (CustomerID, AccountType, Balance, IsActive)
    VALUES (@NewCustomerID, 'Savings', 0.00, 1);

    SET @Salt = CRYPT_GEN_RANDOM(32);
    INSERT INTO dbo.UserLogin (Username, PasswordHash, Salt, CustomerID, UserType, PasswordLastChanged, IsActive)
    VALUES ('SmartBank_Customer2', dbo.fn_HashPassword('Customer2P@ss!', @Salt), @Salt,
            @NewCustomerID, 'Customer', SYSDATETIME(), 1);
END

CLOSE SYMMETRIC KEY CLE_ICNumber_SymKey;
GO

PRINT 'Part 12 (Test Identity Seed) setup complete -- 8 identities available for SQL Auth demo.';
GO