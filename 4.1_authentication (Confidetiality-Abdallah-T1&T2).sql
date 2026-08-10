USE SmartBankDB;
GO

-- ================================================================
-- TASK #1: LOGIN SYSTEM (sp_Login, sp_Logout)
-- ================================================================

-- ----------------------------------------------------------------
-- Component: Schema support for login (adds PasswordLastChanged
-- column needed for the password expiration check further down)
-- ----------------------------------------------------------------
ALTER TABLE dbo.UserLogin
ADD PasswordLastChanged DATETIME2 NOT NULL DEFAULT SYSDATETIME();
GO

-- ----------------------------------------------------------------
-- Component: Account lockout settings + Password expiration
-- (a small settings table so the numbers below aren't hardcoded
-- inside the procedure -- makes them easy to point to and explain
-- during the demo, and easy to change later without editing code)
-- ----------------------------------------------------------------
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

-- ================================================================
-- Component: sp_Login stored procedure
-- (Fixes Weakness 1: "No authentication mechanism" -- this is the
-- procedure that finally checks who someone is before letting them
-- touch anything.)
-- ================================================================
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
            @MaxAttempts INT, @LockoutMinutes INT, @ExpiryDays INT;

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

    -- ------------------------------------------------------------
    -- Component: Generic error messages
    -- (Unknown username gets the SAME message as a wrong password,
    -- so an attacker can't tell which one they got wrong.)
    -- ------------------------------------------------------------
    IF @LoginID IS NULL
    BEGIN
        SET @Message = 'Invalid username or password.';
        RETURN;
    END

    IF @IsActive = 0
    BEGIN
        SET @Message = 'Invalid username or password.';
        RETURN;
    END

    -- ------------------------------------------------------------
    -- Component: Account lockout after failed attempts
    -- (Fixes part of Weakness 3 -- refuses to even check the
    -- password if the account is currently locked out.)
    -- ------------------------------------------------------------
    IF @LockoutUntil IS NOT NULL AND @LockoutUntil > SYSDATETIME()
    BEGIN
        SET @Message = 'Account temporarily locked. Please try again later.';
        RETURN;
    END

    -- ------------------------------------------------------------
    -- Component: Password verification (hash comparison) + Salting
    -- (Fixes Weakness 18 -- password is never compared as plain
    -- text. We hash what they typed, using their unique salt, and
    -- compare it to the stored hash. SHA2_512 matches the 64-byte
    -- PasswordHash column already defined in the schema.)
    -- ------------------------------------------------------------
    IF HASHBYTES('SHA2_512', @Salt + CONVERT(VARBINARY(4000), @PlainPassword)) = @StoredHash
    BEGIN
        -- --------------------------------------------------------
        -- Component: Password expiration
        -- (Fixes part of Weakness 3 -- correct password, but if
        -- it's too old, block login and demand a change instead.)
        -- --------------------------------------------------------
        IF DATEDIFF(DAY, @PasswordLastChanged, SYSDATETIME()) > @ExpiryDays
        BEGIN
            SET @PasswordExpired = 1;
            SET @Success = 0;
            SET @Message = 'Password has expired. Please change your password to continue.';
            UPDATE dbo.UserLogin
            SET FailedLoginAttempts = 0, LockoutUntil = NULL
            WHERE LoginID = @LoginID;
            RETURN;
        END

        -- --------------------------------------------------------
        -- Component: Setting SESSION_CONTEXT on success
        -- (Fixes the "who is this" problem for every later task --
        -- Task #5's row-filtering AND D's transaction procedures
        -- both read these values to know who's logged in.)
        -- --------------------------------------------------------
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
        -- --------------------------------------------------------
        -- Component: Account lockout after failed attempts
        -- (Wrong password -- count it, and lock the account if
        -- this attempt pushes the count to the configured limit.)
        -- --------------------------------------------------------
        UPDATE dbo.UserLogin
        SET FailedLoginAttempts = FailedLoginAttempts + 1,
            LockoutUntil = CASE WHEN FailedLoginAttempts + 1 >= @MaxAttempts
                                 THEN DATEADD(MINUTE, @LockoutMinutes, SYSDATETIME())
                                 ELSE LockoutUntil END
        WHERE LoginID = @LoginID;

        SET @Message = 'Invalid username or password.';
    END
END;
GO

-- ================================================================
-- Component: sp_Logout procedure
-- (Small companion to sp_Login -- clears the SESSION_CONTEXT
-- values so the session no longer "remembers" who was logged in.)
-- ================================================================
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


-- ================================================================
-- TASK #6 TEST CASES -- for Task #1 (Login System)
-- Run these immediately after building the code above, in the
-- SAME SSMS session, before moving on to Task #2. Highlight each
-- block below and press F5 to run just that block, so you can see
-- each result before running the next one.
-- ================================================================

-- Setup: give one seeded demo account a real password to test with
-- (only needs to be run ONCE, not every time you test)
DECLARE @TestSalt VARBINARY(32) = CRYPT_GEN_RANDOM(32);
DECLARE @TestPassword NVARCHAR(100) = 'Test1234!';

UPDATE dbo.UserLogin
SET Salt = @TestSalt,
    PasswordHash = HASHBYTES('SHA2_512', @TestSalt + CONVERT(VARBINARY(4000), @TestPassword)),
    PasswordLastChanged = SYSDATETIME()
WHERE Username = 'staff_hafizzainal';
GO

-- TEST CASE 1: Correct username + correct password -> should succeed
DECLARE @Success BIT, @Expired BIT, @Msg NVARCHAR(200);
EXEC sp_Login 'staff_hafizzainal', 'Test1234!', @Success OUTPUT, @Expired OUTPUT, @Msg OUTPUT;
SELECT @Success AS Success, @Expired AS Expired, @Msg AS Message;
-- Expected: Success = 1, Message = 'Login successful.'

-- TEST CASE 2: Correct username + WRONG password -> should fail, generic message
DECLARE @Success2 BIT, @Expired2 BIT, @Msg2 NVARCHAR(200);
EXEC sp_Login 'staff_hafizzainal', 'WrongPassword', @Success2 OUTPUT, @Expired2 OUTPUT, @Msg2 OUTPUT;
SELECT @Success2 AS Success, @Expired2 AS Expired, @Msg2 AS Message;
-- Expected: Success = 0, Message = 'Invalid username or password.'

-- TEST CASE 3: Unknown username -> should fail, SAME generic message as test 2
DECLARE @Success3 BIT, @Expired3 BIT, @Msg3 NVARCHAR(200);
EXEC sp_Login 'not_a_real_user', 'AnyPassword', @Success3 OUTPUT, @Expired3 OUTPUT, @Msg3 OUTPUT;
SELECT @Success3 AS Success, @Expired3 AS Expired, @Msg3 AS Message;
-- Expected: Success = 0, Message = 'Invalid username or password.'

-- TEST CASE 4: Lockout -- run TEST CASE 2 two more times (3 total wrong
-- attempts), then try the CORRECT password again
DECLARE @Success4 BIT, @Expired4 BIT, @Msg4 NVARCHAR(200);
EXEC sp_Login 'staff_hafizzainal', 'Test1234!', @Success4 OUTPUT, @Expired4 OUTPUT, @Msg4 OUTPUT;
SELECT @Success4 AS Success, @Expired4 AS Expired, @Msg4 AS Message;
-- Expected: Success = 0, Message = 'Account temporarily locked...'
-- even though the password is CORRECT this time -- proves lockout works

-- TEST CASE 5: SESSION_CONTEXT check -- after a successful login,
-- confirm the values were actually set
SELECT
    SESSION_CONTEXT(N'UserType')   AS SessionUserType,
    SESSION_CONTEXT(N'StaffID')    AS SessionStaffID,
    SESSION_CONTEXT(N'CustomerID') AS SessionCustomerID;
-- Expected: shows the logged-in user's UserType and StaffID (run this
-- right after a SUCCESSFUL login test, in the same query window)

-- TEST CASE 6: sp_Logout clears the session
EXEC sp_Logout;
SELECT
    SESSION_CONTEXT(N'UserType')   AS SessionUserType,
    SESSION_CONTEXT(N'StaffID')    AS SessionStaffID,
    SESSION_CONTEXT(N'CustomerID') AS SessionCustomerID;
-- Expected: all NULL now

USE SmartBankDB;
GO

-- ================================================================
-- TASK #2: CHANGE PASSWORD FEATURE (sp_ChangePassword)
-- ================================================================

-- ----------------------------------------------------------------
-- Component: Password complexity check
-- (Fixes Weakness 3 -- rejects weak new passwords before they can
-- ever be saved. Requires 8+ characters, at least one uppercase,
-- one lowercase, one digit, and one special character.)
-- ----------------------------------------------------------------
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

-- ================================================================
-- Component: sp_ChangePassword stored procedure
-- ================================================================
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

    -- ------------------------------------------------------------
    -- Component: Password complexity check
    -- (Check the NEW password before touching anything else --
    -- no point verifying the old password if the new one is
    -- going to be rejected anyway.)
    -- ------------------------------------------------------------
    IF dbo.fn_ValidatePasswordComplexity(@NewPassword) = 0
    BEGIN
        SET @Message = 'New password must be at least 8 characters and include an uppercase letter, a lowercase letter, a digit, and a special character.';
        RETURN;
    END

    DECLARE @LoginID INT, @StoredHash VARBINARY(64), @Salt VARBINARY(32),
            @IsActive BIT, @LockoutUntil DATETIME2,
            @MaxAttempts INT, @LockoutMinutes INT;

    SELECT @MaxAttempts    = ConfigValue FROM dbo.SecurityConfig WHERE ConfigKey = 'MaxFailedAttempts';
    SELECT @LockoutMinutes = ConfigValue FROM dbo.SecurityConfig WHERE ConfigKey = 'LockoutMinutes';

    SELECT @LoginID = LoginID, @StoredHash = PasswordHash, @Salt = Salt,
           @IsActive = IsActive, @LockoutUntil = LockoutUntil
    FROM dbo.UserLogin
    WHERE Username = @Username;

    -- Unknown or deactivated account -- generic message, same idea as Task #1
    IF @LoginID IS NULL OR @IsActive = 0
    BEGIN
        SET @Message = 'Current password is incorrect.';
        RETURN;
    END

    -- ------------------------------------------------------------
    -- Component: Reuse the lockout mechanism for wrong old-password attempts
    -- ------------------------------------------------------------
    IF @LockoutUntil IS NOT NULL AND @LockoutUntil > SYSDATETIME()
    BEGIN
        SET @Message = 'This account is temporarily locked. Please try again later.';
        RETURN;
    END

    -- ------------------------------------------------------------
    -- Component: Verify old password first
    -- ------------------------------------------------------------
    IF HASHBYTES('SHA2_512', @Salt + CONVERT(VARBINARY(4000), @OldPassword)) <> @StoredHash
    BEGIN
        -- Wrong old password -- counts as a failed attempt, same as Task #1
        UPDATE dbo.UserLogin
        SET FailedLoginAttempts = FailedLoginAttempts + 1,
            LockoutUntil = CASE WHEN FailedLoginAttempts + 1 >= @MaxAttempts
                                 THEN DATEADD(MINUTE, @LockoutMinutes, SYSDATETIME())
                                 ELSE LockoutUntil END
        WHERE LoginID = @LoginID;

        SET @Message = 'Current password is incorrect.';
        RETURN;
    END

    -- ------------------------------------------------------------
    -- Component: New random salt + New hash using SHA2_512
    -- + Reset PasswordLastChanged + Reset lockout state on success
    -- ------------------------------------------------------------
    DECLARE @NewSalt VARBINARY(32) = CRYPT_GEN_RANDOM(32);

    UPDATE dbo.UserLogin
    SET PasswordHash         = HASHBYTES('SHA2_512', @NewSalt + CONVERT(VARBINARY(4000), @NewPassword)),
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
-- TASK #6 TEST CASES -- for Task #2 (Change Password)
-- Run in the SAME query window, right after building the code
-- above. Highlight each block and press F5 individually.
-- ================================================================

-- TEST CASE 1: Correct old password + strong new password -> succeeds
DECLARE @Success BIT, @Msg NVARCHAR(200);
EXEC sp_ChangePassword 'staff_hafizzainal', 'Test1234!', 'NewPass99!', @Success OUTPUT, @Msg OUTPUT;
SELECT @Success AS Success, @Msg AS Message;
-- Expected: Success = 1, Message = 'Password changed successfully.'

-- TEST CASE 2: Confirm the NEW password actually works for login now
DECLARE @Success2 BIT, @Expired2 BIT, @Msg2 NVARCHAR(200);
EXEC sp_Login 'staff_hafizzainal', 'NewPass99!', @Success2 OUTPUT, @Expired2 OUTPUT, @Msg2 OUTPUT;
SELECT @Success2 AS Success, @Msg2 AS Message;
-- Expected: Success = 1

-- TEST CASE 3: Weak new password -> rejected before anything else is checked
DECLARE @Success3 BIT, @Msg3 NVARCHAR(200);
EXEC sp_ChangePassword 'staff_hafizzainal', 'NewPass99!', 'weak', @Success3 OUTPUT, @Msg3 OUTPUT;
SELECT @Success3 AS Success, @Msg3 AS Message;
-- Expected: Success = 0, complexity error message

-- TEST CASE 4: Wrong OLD password -> rejected, generic message
DECLARE @Success4 BIT, @Msg4 NVARCHAR(200);
EXEC sp_ChangePassword 'staff_hafizzainal', 'WrongOldPassword', 'AnotherStrong1!', @Success4 OUTPUT, @Msg4 OUTPUT;
SELECT @Success4 AS Success, @Msg4 AS Message;
-- Expected: Success = 0, 'Current password is incorrect.'

-- TEST CASE 5: Lockout via change-password -- run TEST CASE 4's block
-- two more times (3 wrong attempts total), then try again with
-- the CORRECT current password
DECLARE @Success5 BIT, @Msg5 NVARCHAR(200);
EXEC sp_ChangePassword 'staff_hafizzainal', 'NewPass99!', 'AnotherStrong1!', @Success5 OUTPUT, @Msg5 OUTPUT;
SELECT @Success5 AS Success, @Msg5 AS Message;
-- Expected: Success = 0, 'This account is temporarily locked...'
-- even with the CORRECT old password -- proves shared lockout works