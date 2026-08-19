-- SALSABILA (TP078641) CONFIDENTIALITY TC3 // HASHING AND SALTING
/* ================================================================
   Task C3: Password hashing and salting (SHA2_512 + per-user salt), so
   that no one — including the DBA — can ever recover a real
   password from the database.

   Report reference : Section 3.3 (Hashing), 4.7
   Weakness addressed: Weakness 18 (no password hashing strategy)
   ================================================================ */

-- IMPLEMENTATION >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

USE SmartBankDB;
GO

/* ================================================================
   [C3.1] HASHING FUNCTION
   Combines a plaintext password with a per-user salt and produces
   a 64-byte SHA2_512 hash — matching UserLogin.PasswordHash's
   declared type, VARBINARY(64).
   ================================================================ */
CREATE OR ALTER FUNCTION dbo.fn_HashPassword
(
    @PlainPassword NVARCHAR(100),
    @Salt VARBINARY(32)
)
RETURNS VARBINARY(64)
AS
BEGIN
    RETURN HASHBYTES('SHA2_512', CONVERT(VARBINARY(MAX), @PlainPassword) + @Salt);
END;
GO

/* ================================================================
   [C3.2] SET/RESET PASSWORD PROCEDURE
   Generates a NEW random salt (CRYPT_GEN_RANDOM — a cryptographically
   secure random byte generator, not a predictable pseudo-random one)
   every time a password is set, then stores the resulting hash.
   Basic input validation rejects NULL/empty passwords defensively.

   COORDINATION NOTE for Person B: sp_ChangePassword and any account
   registration procedure (sp_ManageStaff / sp_ManageCustomer, when
   creating a new UserLogin row) should call this procedure rather
   than writing separate hashing logic, so there is exactly one
   place in the whole system that knows how hashing works.
   ================================================================ */
CREATE OR ALTER PROCEDURE dbo.sp_SetPassword
    @Username NVARCHAR(50),
    @NewPassword NVARCHAR(100)
AS
BEGIN
    SET NOCOUNT ON;

    IF @NewPassword IS NULL OR LEN(@NewPassword) < 1
    BEGIN
        THROW 51002, 'Password cannot be NULL or empty.', 1;
        RETURN;
    END

    DECLARE @NewSalt VARBINARY(32) = CRYPT_GEN_RANDOM(32);
    DECLARE @NewHash VARBINARY(64) = dbo.fn_HashPassword(@NewPassword, @NewSalt);

    UPDATE dbo.UserLogin
    SET Salt = @NewSalt,
        PasswordHash = @NewHash
    WHERE Username = @Username;

    IF @@ROWCOUNT = 0
    BEGIN
        THROW 51003, 'Username not found.', 1;
    END
END;
GO

/* ================================================================
   [C3.3] VERIFY PASSWORD FUNCTION
   Recomputes the hash of a supplied password using the user's
   STORED salt, and compares it against the stored hash. Returns
   1 (match) or 0 (no match / user not found).

   COORDINATION NOTE for Person B: sp_Login should call this
   function to check a login attempt, e.g.
   IF dbo.fn_VerifyPassword(@Username, @SuppliedPassword) = 1
       -- populate SESSION_CONTEXT, reset FailedLoginAttempts
   ELSE
       -- increment FailedLoginAttempts, check LockoutUntil logic
   ================================================================ */
CREATE OR ALTER FUNCTION dbo.fn_VerifyPassword
(
    @Username NVARCHAR(50),
    @SuppliedPassword NVARCHAR(100)
)
RETURNS BIT
AS
BEGIN
    DECLARE @StoredHash VARBINARY(64);
    DECLARE @StoredSalt VARBINARY(32);
    DECLARE @IsValid BIT = 0;

    SELECT
        @StoredHash = PasswordHash,
        @StoredSalt = Salt
    FROM dbo.UserLogin
    WHERE Username = @Username;

    IF @StoredHash IS NOT NULL
       AND @StoredHash = dbo.fn_HashPassword(@SuppliedPassword, @StoredSalt)
    BEGIN
        SET @IsValid = 1;
    END

    RETURN @IsValid;
END;
GO

/* ================================================================
   [C3.4] ACCESS RESTRICTION
   No GRANT EXECUTE to any business role (DBA, Bank_Manager,
   Bank_Officer, Customer) on fn_HashPassword, sp_SetPassword, or
   fn_VerifyPassword. SQL Server denies by default — since these
   are never granted to anyone, they are reachable ONLY through
   Person B's own procedures (sp_Login, sp_ChangePassword, etc.)
   via ownership chaining, provided those procedures are owned by
   the same principal (dbo) and B correctly restricts who can call
   THEM. This keeps the credential engine itself completely
   inaccessible to direct calls from any role — including DBA.
   ================================================================ */
PRINT 'Reminder: no EXECUTE grants issued on hashing objects — reachable only via Person B''s wrapper procedures.';
GO

/* ================================================================
   [C3.5] MIGRATE SEED DATA
   The baseline seed script assigned every UserLogin row a
   placeholder hash of a random GUID — meaning nobody could ever
   actually log in with any of these demo accounts. This resets
   every seeded account to a single, known demo password so the
   accounts are usable for testing (by you, and later by B/D).

   NOTE: using ONE shared password across all demo accounts is a
   testing convenience only, clearly flagged here — not a
   production practice. Real customers/staff would each set their
   own password via Person B's registration/login flow, which
   calls sp_SetPassword individually per account.
   ================================================================ */
DECLARE @Username NVARCHAR(50);

DECLARE seed_cursor CURSOR FOR
    SELECT Username FROM dbo.UserLogin;

OPEN seed_cursor;
FETCH NEXT FROM seed_cursor INTO @Username;

WHILE @@FETCH_STATUS = 0
BEGIN
    EXEC dbo.sp_SetPassword @Username = @Username, @NewPassword = 'Demo@Pass2026';
    FETCH NEXT FROM seed_cursor INTO @Username;
END

CLOSE seed_cursor;
DEALLOCATE seed_cursor;
GO

PRINT 'C3.5 — all seeded demo accounts now use password: Demo@Pass2026';
GO

/* ================================================================
   [C3.6] ONE-WAY DESIGN — NO CODE, DOCUMENTATION ONLY
   Unlike C2's CLE (ENCRYPTBYKEY / DECRYPTBYKEY pair), T-SQL's
   HASHBYTES has NO corresponding reversal function. There is no
   "un-hash" operation available in SQL Server at all — this is a
   structural guarantee, not a permission-based one. Even a
   sysadmin with full CONTROL SERVER rights cannot recover a
   plaintext password from a SHA2_512 hash; the only possible
   attack is guessing candidate passwords and re-hashing them to
   compare (which is exactly what salting defends against by
   making that attack expensive and non-reusable across accounts).
   ================================================================ */

PRINT 'C3 — Password hashing and salting setup complete.';

-- TEST CASE >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
/* ================================================================
   Reuses test_dba_user, test_manager_user, test_officer_user,
   test_customer_user from the C2 test suite — no need to recreate
   them if C2's test file was already run and its cleanup section
   was NOT run (or was re-run via C2's setup block, which uses
   IF NOT EXISTS guards and is safe to re-run).
   ================================================================ */

USE SmartBankDB;
GO

/* ================================================================
   ONE-TIME SETUP CHECK — confirm test users exist; recreate if
   this is a fresh session where C2's test users were cleaned up.
   ================================================================ */
USE master;
GO

IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name = 'test_manager_login')
    CREATE LOGIN test_manager_login WITH PASSWORD = 'Str0ngTestPass!123';
IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name = 'test_officer_login')
    CREATE LOGIN test_officer_login WITH PASSWORD = 'Str0ngTestPass!123';
GO

USE SmartBankDB;
GO

IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = 'test_manager_user')
    CREATE USER test_manager_user FOR LOGIN test_manager_login;
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = 'test_officer_user')
    CREATE USER test_officer_user FOR LOGIN test_officer_login;
GO

IF NOT EXISTS (SELECT 1 FROM sys.database_role_members drm
                JOIN sys.database_principals r ON drm.role_principal_id = r.principal_id
                JOIN sys.database_principals m ON drm.member_principal_id = m.principal_id
                WHERE r.name = 'Bank_Manager' AND m.name = 'test_manager_user')
    ALTER ROLE Bank_Manager ADD MEMBER test_manager_user;
IF NOT EXISTS (SELECT 1 FROM sys.database_role_members drm
                JOIN sys.database_principals r ON drm.role_principal_id = r.principal_id
                JOIN sys.database_principals m ON drm.member_principal_id = m.principal_id
                WHERE r.name = 'Bank_Officer' AND m.name = 'test_officer_user')
    ALTER ROLE Bank_Officer ADD MEMBER test_officer_user;
GO


/* ================================================================
   T-C3.1 — POSITIVE: hash output is correctly sized and non-null
   ================================================================ */
PRINT '--- T-C3.1: checking hash output size ---';

SELECT
    dbo.fn_HashPassword('TestPassword123', CRYPT_GEN_RANDOM(32)) AS SampleHash,
    DATALENGTH(dbo.fn_HashPassword('TestPassword123', CRYPT_GEN_RANDOM(32))) AS HashByteLength;
-- Expected: HashByteLength = 64 (matches PasswordHash VARBINARY(64))
GO


/* ================================================================
   T-C3.2 — POSITIVE: sp_SetPassword correctly updates a test account
   ================================================================ */
PRINT '--- T-C3.2: setting a known password on a test account ---';

EXEC dbo.sp_SetPassword @Username = 'staff_aisharahman', @NewPassword = 'MyTestPass!1';

SELECT Username, DATALENGTH(PasswordHash) AS HashLen, DATALENGTH(Salt) AS SaltLen
FROM dbo.UserLogin
WHERE Username = 'staff_aisharahman';
-- Expected: HashLen = 64, SaltLen = 32
GO


/* ================================================================
   T-C3.3 — POSITIVE: fn_VerifyPassword returns 1 for correct password
   ================================================================ */
PRINT '--- T-C3.3: verifying the CORRECT password ---';

SELECT dbo.fn_VerifyPassword('staff_aisharahman', 'MyTestPass!1') AS ShouldBeOne;
GO


/* ================================================================
   T-C3.4 — NEGATIVE: fn_VerifyPassword returns 0 for wrong password
   ================================================================ */
PRINT '--- T-C3.4: verifying an INCORRECT password ---';

SELECT dbo.fn_VerifyPassword('staff_aisharahman', 'WrongPassword') AS ShouldBeZero;
GO


/* ================================================================
   T-C3.5 — POSITIVE: same password on two accounts produces
   DIFFERENT hashes (proves per-user salting is working)
   ================================================================ */
PRINT '--- T-C3.5: same password, two accounts, comparing hashes ---';

EXEC dbo.sp_SetPassword @Username = 'staff_aisharahman', @NewPassword = 'SamePassword99';
EXEC dbo.sp_SetPassword @Username = 'cust_aimanhaziq',   @NewPassword = 'SamePassword99';

SELECT Username, PasswordHash, Salt
FROM dbo.UserLogin
WHERE Username IN ('staff_aisharahman', 'cust_aimanhaziq');
-- Expected: PasswordHash values are DIFFERENT despite identical
-- plaintext password, because Salt is different for each row
GO


/* ================================================================
   T-C3.6 — POSITIVE: all seeded demo accounts are usable
   ================================================================ */
PRINT '--- T-C3.6: bulk-checking demo accounts can authenticate ---';

SELECT TOP 10
    Username,
    dbo.fn_VerifyPassword(Username, 'Demo@Pass2026') AS CanLogin
FROM dbo.UserLogin
WHERE Username NOT IN ('staff_aisharahman', 'cust_aimanhaziq'); -- excluded: overwritten in T-C3.2/T-C3.5 above
-- Expected: CanLogin = 1 for every row shown
GO


/* ================================================================
   T-C3.7 — NEGATIVE: non-privileged role blocked from sp_SetPassword
   ================================================================ */
PRINT '--- T-C3.7: Bank_Officer attempting to call sp_SetPassword directly ---';

EXECUTE AS USER = 'test_officer_user';
EXEC dbo.sp_SetPassword @Username = 'staff_aisharahman', @NewPassword = 'Hacked!123';
-- Expected: Msg 229 EXECUTE permission denied
REVERT;
GO


/* ================================================================
   T-C3.8 — NEGATIVE: non-privileged role blocked from fn_VerifyPassword
   ================================================================ */
PRINT '--- T-C3.8: Bank_Officer attempting to call fn_VerifyPassword directly ---';

EXECUTE AS USER = 'test_officer_user';
SELECT dbo.fn_VerifyPassword('staff_aisharahman', 'anything');
-- Expected: permission denied error (function has no grant to Bank_Officer)
REVERT;
GO


/* ================================================================
   T-C3.9 — NEGATIVE: sp_SetPassword rejects NULL/empty password
   ================================================================ */
PRINT '--- T-C3.9: attempting to set a NULL password ---';

EXEC dbo.sp_SetPassword @Username = 'staff_aisharahman', @NewPassword = NULL;
-- Expected: Msg 51002 "Password cannot be NULL or empty."
GO


/* ================================================================
   CLEANUP — restore the two test accounts touched above back to
   the shared demo password, so C3.6's demo-account guarantee
   holds true for the whole seed set again.
   ================================================================ */
PRINT '--- Restoring demo password on accounts modified during testing ---';

EXEC dbo.sp_SetPassword @Username = 'staff_aisharahman', @NewPassword = 'Demo@Pass2026';
EXEC dbo.sp_SetPassword @Username = 'cust_aimanhaziq',   @NewPassword = 'Demo@Pass2026';
GO

PRINT 'C3 test suite complete.';