DECLARE @Success BIT;
DECLARE @Message NVARCHAR(200);

EXEC dbo.sp_ProcessTransaction
    @AccountID = 1,
    @ToAccountID = NULL,
    @Amount = 100,
    @TransactionType = 'Deposit',
    @Success = @Success OUTPUT,
    @Message = @Message OUTPUT;