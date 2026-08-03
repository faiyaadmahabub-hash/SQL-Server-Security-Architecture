USE SmartBankDB;
GO

-- 4.1 Authentication and Password Policy

-- Fix PasswordHash size to match SHA2_256 output (32 bytes)
ALTER TABLE dbo.UserLogin
ALTER COLUMN PasswordHash VARBINARY(32) NOT NULL;
GO

-- Track password age for expiration policy
ALTER TABLE dbo.UserLogin
ADD PasswordLastChanged DATETIME2 NOT NULL DEFAULT SYSDATETIME();
GO

-- Configurable security policy values
CREATE TABLE dbo.SecurityConfig (
    ConfigKey   NVARCHAR(50) NOT NULL PRIMARY KEY,
    ConfigValue INT          NOT NULL
);
GO

INSERT INTO dbo.SecurityConfig (ConfigKey, ConfigValue)
VALUES ('MaxFailedAttempts', 5), ('LockoutMinutes', 15), ('PasswordExpiryDays', 90);
GO

-- Add LOGIN/LOGOUT as explicit audit action types
ALTER TABLE dbo.AuditLog DROP CONSTRAINT CHK_ActionType;
GO
ALTER TABLE dbo.AuditLog ADD CONSTRAINT CHK_ActionType
    CHECK (ActionType IN ('INSERT', 'UPDATE', 'DELETE', 'REJECTED', 'LOGIN', 'LOGOUT'));
GO

-- Password complexity: 8+ chars, upper, lower, digit, special
CREATE OR ALTER FUNCTION dbo.fn_ValidatePasswordComplexity (@PlainPassword NVARCHAR(100))
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

-- Authenticates user, enforces lockout/expiration, sets SESSION_CONTEXT
CREATE OR ALTER PROCEDURE dbo.sp_Login
    @Username         NVARCHAR(50),
    @PlainPassword    NVARCHAR(100),
    @Success          BIT OUTPUT,
    @PasswordExpired  BIT OUTPUT,
    @Message          NVARCHAR(200) OUTPUT
WITH EXECUTE AS OWNER
AS
BEGIN
    SET NOCOUNT ON;
    SET @Success = 0;
    SET @PasswordExpired = 0;

    DECLARE @LoginID INT, @StoredHash VARBINARY(32), @Salt VARBINARY(32),
            @StaffID INT, @CustomerID INT, @UserType NVARCHAR(10),
            @LockoutUntil DATETIME2, @IsActive BIT,
            @PasswordLastChanged DATETIME2, @MaxAttempts INT, @LockoutMinutes INT;

    SELECT @LoginID = LoginID, @StoredHash = PasswordHash, @Salt = Salt,
           @StaffID = StaffID, @CustomerID = CustomerID, @UserType = UserType,
           @LockoutUntil = LockoutUntil, @IsActive = IsActive,
           @PasswordLastChanged = PasswordLastChanged
    FROM dbo.UserLogin
    WHERE Username = @Username;

    -- Unknown username
    IF @LoginID IS NULL
    BEGIN
        SET @Message = 'Invalid username or password.';
        INSERT INTO dbo.AuditLog (TableName, ColumnName, OldValue, NewValue, ChangedBy, ActionType)
        VALUES ('UserLogin', 'Username', NULL, 'Login attempt: unknown username', @Username, 'REJECTED');
        RETURN;
    END

    -- Deactivated account
    IF @IsActive = 0
    BEGIN
        SET @Message = 'Invalid username or password.';
        INSERT INTO dbo.AuditLog (TableName, ColumnName, OldValue, NewValue, ChangedBy, ActionType)
        VALUES ('UserLogin', 'IsActive', NULL, 'Login attempt on inactive account', @Username, 'REJECTED');
        RETURN;
    END

    -- Locked account
    IF @LockoutUntil IS NOT NULL AND @LockoutUntil > SYSDATETIME()
    BEGIN
        SET @Message = 'Account temporarily locked. Try again later.';
        INSERT INTO dbo.AuditLog (TableName, ColumnName, OldValue, NewValue, ChangedBy, ActionType)
        VALUES ('UserLogin', 'LockoutUntil', NULL, 'Login attempt while account locked', @Username, 'REJECTED');
        RETURN;
    END

    -- Verify password hash
    IF HASHBYTES('SHA2_256', @Salt + CONVERT(VARBINARY(4000), @PlainPassword)) = @StoredHash
    BEGIN
        -- Check password expiration
        DECLARE @ExpiryDays INT;
        SELECT @ExpiryDays = ConfigValue FROM dbo.SecurityConfig WHERE ConfigKey = 'PasswordExpiryDays';

        IF DATEDIFF(DAY, @PasswordLastChanged, SYSDATETIME()) > @ExpiryDays
        BEGIN
            SET @PasswordExpired = 1;
            SET @Success = 0;
            SET @Message = 'Password has expired. Please change your password to continue.';

            UPDATE dbo.UserLogin
            SET FailedLoginAttempts = 0, LockoutUntil = NULL
            WHERE LoginID = @LoginID;

            INSERT INTO dbo.AuditLog (TableName, ColumnName, OldValue, NewValue, ChangedBy, ActionType)
            VALUES ('UserLogin', 'PasswordLastChanged', NULL, 'Login blocked: password expired', @Username, 'REJECTED');

            RETURN;
        END

        -- Success: reset counters, set session context, log it
        SET @Success = 1;
        SET @Message = 'Login successful.';

        UPDATE dbo.UserLogin
        SET FailedLoginAttempts = 0, LockoutUntil = NULL, LastLogin = SYSDATETIME()
        WHERE LoginID = @LoginID;

        EXEC sys.sp_set_session_context @key = N'UserType',   @value = @UserType;
        EXEC sys.sp_set_session_context @key = N'StaffID',    @value = @StaffID;
        EXEC sys.sp_set_session_context @key = N'CustomerID', @value = @CustomerID;

        INSERT INTO dbo.AuditLog (TableName, ColumnName, OldValue, NewValue, ChangedBy, ActionType)
        VALUES ('UserLogin', 'LastLogin', NULL, 'Successful login', @Username, 'LOGIN');

        -- TODO (4.6): open CLE symmetric key here for Bank Officer sessions
    END
    ELSE
    BEGIN
        -- Wrong password: atomic increment + lockout check
        SELECT @MaxAttempts    = ConfigValue FROM dbo.SecurityConfig WHERE ConfigKey = 'MaxFailedAttempts';
        SELECT @LockoutMinutes = ConfigValue FROM dbo.SecurityConfig WHERE ConfigKey = 'LockoutMinutes';

        UPDATE dbo.UserLogin
        SET FailedLoginAttempts = FailedLoginAttempts + 1,
            LockoutUntil = CASE WHEN FailedLoginAttempts + 1 >= @MaxAttempts
                                 THEN DATEADD(MINUTE, @LockoutMinutes, SYSDATETIME())
                                 ELSE LockoutUntil END
        WHERE LoginID = @LoginID;

        SET @Message = 'Invalid username or password.';

        INSERT INTO dbo.AuditLog (TableName, ColumnName, OldValue, NewValue, ChangedBy, ActionType)
        VALUES ('UserLogin', 'PasswordHash', NULL, 'Failed login attempt', @Username, 'REJECTED');
    END
END;
GO

-- Logs logout and clears SESSION_CONTEXT
CREATE OR ALTER PROCEDURE dbo.sp_Logout
    @Username NVARCHAR(50)
WITH EXECUTE AS OWNER
AS
BEGIN
    SET NOCOUNT ON;

    INSERT INTO dbo.AuditLog (TableName, ColumnName, OldValue, NewValue, ChangedBy, ActionType)
    VALUES ('UserLogin', NULL, NULL, 'Logout', @Username, 'LOGOUT');

    EXEC sys.sp_set_session_context @key = N'UserType',   @value = NULL;
    EXEC sys.sp_set_session_context @key = N'StaffID',    @value = NULL;
    EXEC sys.sp_set_session_context @key = N'CustomerID', @value = NULL;
END;
GO

-- Verifies old password, enforces policy, sets new hash+salt
CREATE OR ALTER PROCEDURE dbo.sp_ChangePassword
    @Username    NVARCHAR(50),
    @OldPassword NVARCHAR(100),
    @NewPassword NVARCHAR(100),
    @Success     BIT OUTPUT,
    @Message     NVARCHAR(200) OUTPUT
WITH EXECUTE AS OWNER
AS
BEGIN
    SET NOCOUNT ON;
    SET @Success = 0;

    -- Reject weak new password
    IF dbo.fn_ValidatePasswordComplexity(@NewPassword) = 0
    BEGIN
        SET @Message = 'New password must be at least 8 characters and include an uppercase letter, a lowercase letter, a digit, and a special character.';
        INSERT INTO dbo.AuditLog (TableName, ColumnName, OldValue, NewValue, ChangedBy, ActionType)
        VALUES ('UserLogin', 'PasswordHash', NULL, 'Rejected new password: policy violation', @Username, 'REJECTED');
        RETURN;
    END

    DECLARE @LoginID INT, @StoredHash VARBINARY(32), @Salt VARBINARY(32),
            @IsActive BIT, @LockoutUntil DATETIME2, @MaxAttempts INT, @LockoutMinutes INT;

    SELECT @LoginID = LoginID, @StoredHash = PasswordHash, @Salt = Salt,
           @IsActive = IsActive, @LockoutUntil = LockoutUntil
    FROM dbo.UserLogin WHERE Username = @Username;

    -- Unknown or inactive account
    IF @LoginID IS NULL OR @IsActive = 0
    BEGIN
        SET @Message = 'Current password is incorrect.';
        RETURN;
    END

    -- Locked account
    IF @LockoutUntil IS NOT NULL AND @LockoutUntil > SYSDATETIME()
    BEGIN
        SET @Message = 'This account is temporarily locked. Please try again later.';
        RETURN;
    END

    -- Verify old password
    IF HASHBYTES('SHA2_256', @Salt + CONVERT(VARBINARY(4000), @OldPassword)) <> @StoredHash
    BEGIN
        -- Wrong password: same atomic lockout protection as sp_Login
        SELECT @MaxAttempts    = ConfigValue FROM dbo.SecurityConfig WHERE ConfigKey = 'MaxFailedAttempts';
        SELECT @LockoutMinutes = ConfigValue FROM dbo.SecurityConfig WHERE ConfigKey = 'LockoutMinutes';

        UPDATE dbo.UserLogin
        SET FailedLoginAttempts = FailedLoginAttempts + 1,
            LockoutUntil = CASE WHEN FailedLoginAttempts + 1 >= @MaxAttempts
                                 THEN DATEADD(MINUTE, @LockoutMinutes, SYSDATETIME())
                                 ELSE LockoutUntil END
        WHERE LoginID = @LoginID;

        SET @Message = 'Current password is incorrect.';
        INSERT INTO dbo.AuditLog (TableName, ColumnName, OldValue, NewValue, ChangedBy, ActionType)
        VALUES ('UserLogin', 'PasswordHash', NULL,
                'Failed password-change attempt: wrong current password', @Username, 'REJECTED');
        RETURN;
    END

    -- Set new salt + hash, reset lockout state
    DECLARE @NewSalt VARBINARY(32) = CRYPT_GEN_RANDOM(32);
    UPDATE dbo.UserLogin
    SET PasswordHash = HASHBYTES('SHA2_256', @NewSalt + CONVERT(VARBINARY(4000), @NewPassword)),
        Salt = @NewSalt,
        PasswordLastChanged = SYSDATETIME(),
        FailedLoginAttempts = 0,
        LockoutUntil = NULL
    WHERE LoginID = @LoginID;

    SET @Success = 1;
    SET @Message = 'Password changed successfully.';

    INSERT INTO dbo.AuditLog (TableName, ColumnName, OldValue, NewValue, ChangedBy, ActionType)
    VALUES ('UserLogin', 'PasswordHash', 'Old hash (not shown)', 'Password changed successfully', @Username, 'UPDATE');
END;
GO