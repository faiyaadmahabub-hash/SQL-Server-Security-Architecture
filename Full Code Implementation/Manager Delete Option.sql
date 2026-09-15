USE SmartBankDB;
GO

CREATE OR ALTER PROCEDURE dbo.sp_ManageStaff
(
    @StaffID INT = NULL,
    @StaffName NVARCHAR(100) = NULL,
    @Position NVARCHAR(50) = NULL,
    @Branch NVARCHAR(100) = NULL,
    @Phone NVARCHAR(20) = NULL,
    @Salary DECIMAL(15,2) = NULL,
    @IsActive BIT = 1,
    @Action NVARCHAR(10) = 'UPDATE',

    @Success BIT OUTPUT,
    @Message NVARCHAR(200) OUTPUT
)
WITH EXECUTE AS OWNER
AS
BEGIN
    SET NOCOUNT ON;

    SET @Success = 0;

    DECLARE @Who NVARCHAR(150) = dbo.fn_GetSessionUsername();


    ----------------------------------------------------
    -- DELETE STAFF
    ----------------------------------------------------
    IF @Action = 'DELETE'
    BEGIN

        IF NOT EXISTS
        (
            SELECT 1
            FROM dbo.Staff
            WHERE StaffID = @StaffID
        )
        BEGIN
            SET @Message = 'Staff record not found.';
            RETURN;
        END


        -- Remove linked login first
        DELETE FROM dbo.UserLogin
        WHERE StaffID = @StaffID;


        -- Delete staff record
        DELETE FROM dbo.Staff
        WHERE StaffID = @StaffID;


        SET @Success = 1;
        SET @Message = 'Staff deleted successfully.';

        RETURN;
    END


    ----------------------------------------------------
    -- CREATE STAFF
    ----------------------------------------------------
    IF @Action = 'CREATE'
    BEGIN

        INSERT INTO dbo.Staff
        (
            StaffName,
            Position,
            Branch,
            Phone,
            Salary,
            IsActive
        )
        VALUES
        (
            @StaffName,
            @Position,
            @Branch,
            @Phone,
            @Salary,
            @IsActive
        );


        SET @Success = 1;
        SET @Message = 'Staff created successfully.';

        RETURN;
    END


    ----------------------------------------------------
    -- UPDATE STAFF
    ----------------------------------------------------
    IF @Action = 'UPDATE'
    BEGIN

        UPDATE dbo.Staff
        SET
            StaffName = @StaffName,
            Branch = @Branch,
            Phone = @Phone,
            Salary = @Salary,
            IsActive = @IsActive
        WHERE StaffID = @StaffID;


        SET @Success = 1;
        SET @Message = 'Staff updated successfully.';

        RETURN;
    END


    SET @Message = 'Invalid action.';
END;
GO


/*Manager can see all of staff details*/

CREATE OR ALTER VIEW dbo.vw_StaffDirectory
AS
SELECT
    StaffID,
    StaffName,
    Phone,
    Position,
    Branch,
    IsActive
FROM dbo.Staff;
GO

