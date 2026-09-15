/*Bank Manager can view Staff details*/
SELECT * FROM dbo.vw_StaffDirectory;
GO

/*new staff record for officer*/
DECLARE @Success BIT,
        @Message NVARCHAR(500);

EXEC dbo.sp_ManageStaff
    @StaffName = 'Test Officer',
    @Position = 'Bank Officer',
    @Branch = 'KL Branch',
    @Phone = '0123456789',
    @Salary = 4500,
    @IsActive = 1,
    @Action = 'CREATE',
    @Success = @Success OUTPUT,
    @Message = @Message OUTPUT;


SELECT 
    @Success AS Success,
    @Message AS Message;
GO


/*Checking for new staff*/
SELECT * FROM dbo.vw_StaffDirectory

/*Checking the details for the new staff*/
SELECT
    StaffID,
    StaffName,
    Phone,
    Position,
    Branch,
    IsActive
FROM dbo.vw_StaffDirectory
WHERE StaffName = 'Test Officer';
GO

/*Update test officer*/
DECLARE @Success BIT,
        @Message NVARCHAR(200);

EXEC dbo.sp_ManageStaff
    @StaffID = 9,
    @StaffName = 'Updated Test Officer',
    @Branch = 'PJ Branch',
    @Phone = '0199999998',
    @Salary = 5000,
    @IsActive = 1,
    @Action = 'UPDATE',
    @Success = @Success OUTPUT,
    @Message = @Message OUTPUT;

SELECT
    @Success AS Success,
    @Message AS Message;
GO


/*Check After Update*/
SELECT
    StaffID,
    StaffName,
    Phone,
    Position,
    Branch,
    IsActive
FROM dbo.vw_StaffDirectory
WHERE StaffName = 'Test Officer';
GO

/*Delete The staff directory that is newly created*/
DECLARE @Success BIT,
        @Message NVARCHAR(200);

EXEC dbo.sp_ManageStaff
    @StaffID = 9,
    @Action = 'DELETE',
    @Success = @Success OUTPUT,
    @Message = @Message OUTPUT;

SELECT 
    @Success AS Success,
    @Message AS Message;
GO

/*Checking after staff deletion*/
SELECT * FROM dbo.vw_StaffDirectory





