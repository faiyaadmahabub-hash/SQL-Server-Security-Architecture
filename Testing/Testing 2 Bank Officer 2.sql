select * from dbo.vw_StaffOwnRecord;
EXEC sp_help 'dbo.sp_UpdateOwnStaffRecord';
EXEC sp_help 'dbo.sp_ManageAccount';


/* CHANGE CUSTOMER ACCOUNT 2 INTO ACTIVE FROM INACTIVE */
DECLARE @Success BIT;
DECLARE @Message NVARCHAR(200);

EXEC dbo.sp_ManageAccount
    @AccountID = 2,
	@CustomerID = 2,
	@AccountType = 'Savings',
	@IsActive = 1,
    @Success = @Success OUTPUT,
    @Message = @Message OUTPUT;

SELECT 
    @Success AS Success,
    @Message AS Message;