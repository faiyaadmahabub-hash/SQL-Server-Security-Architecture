SELECT *
FROM dbo.vw_AccountOwn;
GO


/*Deposit*/
DECLARE @Success BIT,
        @Message NVARCHAR(200);

EXEC dbo.sp_ProcessTransaction
    @AccountID = 1,
    @TransactionType = 'Deposit',
    @Amount = 500,
    @Success = @Success OUTPUT,
    @Message = @Message OUTPUT;

SELECT
    @Success AS Success,
    @Message AS Message;
GO


/*Withdrawal*/
DECLARE @Success BIT,
        @Message NVARCHAR(200);

EXEC dbo.sp_ProcessTransaction
    @AccountID = 1,
    @TransactionType = 'Withdrawal',
    @Amount = 500,
    @Success = @Success OUTPUT,
    @Message = @Message OUTPUT;

SELECT
    @Success AS Success,
    @Message AS Message;
GO


/*Transfer*/
DECLARE @Success BIT,
        @Message NVARCHAR(200);

EXEC dbo.sp_ProcessTransaction
    @AccountID = 1,
    @TransactionType = 'Transfer',
    @Amount = 50,
    @ToAccountID = 2,
    @Success = @Success OUTPUT,
    @Message = @Message OUTPUT;

SELECT
    @Success AS Success,
    @Message AS Message;
GO