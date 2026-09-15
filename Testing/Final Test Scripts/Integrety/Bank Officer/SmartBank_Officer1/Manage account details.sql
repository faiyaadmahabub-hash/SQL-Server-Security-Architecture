
Select * from dbo.vw_AccountAll

/*Create account*/
DECLARE @Success BIT,
        @Message NVARCHAR(200);

EXEC dbo.sp_ManageAccount
    @CustomerID = 1,
    @AccountType = 'Savings',
    @IsActive = 1,
    @Success = @Success OUTPUT,
    @Message = @Message OUTPUT;

SELECT
    @Success AS Success,
    @Message AS Message;
GO

/*Update Account Type*/
DECLARE @Success BIT,
        @Message NVARCHAR(200);

EXEC dbo.sp_ManageAccount
    @AccountID = 4,
    @AccountType = 'Current',
    @IsActive = 1,
    @Success = @Success OUTPUT,
    @Message = @Message OUTPUT;

SELECT 
    @Success AS Success,
    @Message AS Message;
GO




