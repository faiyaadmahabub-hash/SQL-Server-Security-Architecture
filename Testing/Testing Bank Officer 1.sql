select * from dbo.vw_AccountOwn
select * from  dbo.vw_TransactionOwn

DECLARE @Success BIT;
DECLARE @Message NVARCHAR(200);

EXEC dbo.sp_ProcessTransaction
    @AccountID = 2,
    @TransactionType = 'Deposit',
    @Amount = 100,
    @ToAccountID = NULL,
    @Success = @Success OUTPUT,
    @Message = @Message OUTPUT;

SELECT 
    @Success AS Success,
    @Message AS Message;


DECLARE @Success BIT;
DECLARE @Message NVARCHAR(200);
EXEC dbo.sp_ProcessTransaction
    @AccountID = 2,
    @TransactionType = 'Withdrawal',
    @Amount = 50,
    @ToAccountID = NULL,
    @Success = @Success OUTPUT,
    @Message = @Message OUTPUT;

SELECT 
    @Success AS Success,
    @Message AS Message;




DECLARE @Success BIT;
DECLARE @Message NVARCHAR(200);

EXEC dbo.sp_ProcessTransaction
    @AccountID = 2,          -- Customer 2 sender account
    @TransactionType = 'Transfer',
    @Amount = 50,
    @ToAccountID = 1,        -- Customer 1 receiver account
    @Success = @Success OUTPUT,
    @Message = @Message OUTPUT;

SELECT 
    @Success AS Success,
    @Message AS Message;


/* To test if bank officer cannot manage staff*/
DECLARE @Success BIT;
DECLARE @Message NVARCHAR(200);

EXEC dbo.sp_ManageStaff
    @StaffID = 5,
    @StaffName = 'Farah Aina',
    @Position = 'Bank Officer',
    @Branch = 'KL Branch',
    @Phone = '0188888888',
    @Salary = 4500,
    @IsActive = 1,
    @Success = @Success OUTPUT,
    @Message = @Message OUTPUT;


SELECT 
    @Success AS Success,
    @Message AS Message;




DECLARE @Success BIT;
DECLARE @Message NVARCHAR(200);

EXEC dbo.sp_ManageAccount
    @AccountID = 2,
    @CustomerID = 2,
    @AccountType = 'Savings',
    @IsActive = 0,
    @Success = @Success OUTPUT,
    @Message = @Message OUTPUT;


SELECT 
    @Success AS Success,
    @Message AS Message;
