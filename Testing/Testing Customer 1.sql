select * from dbo.vw_AccountOwn;
EXEC sp_help 'dbo.sp_ProcessTransaction';

/* Test Deposit */
DECLARE @Success BIT;
DECLARE @Message NVARCHAR(200);

EXEC dbo.sp_ProcessTransaction
    @AccountID = 1,
    @ToAccountID = NULL,
    @Amount = 100.00,
    @TransactionType = 'Deposit',
    @Success = @Success OUTPUT,
    @Message = @Message OUTPUT;

SELECT
    @Success AS Success,
    @Message AS Message;


/* Verify the balance change */
select * from dbo.vw_TransactionOwn
where AccountID = 1
order by TransDate DESC;


/* Test Withdrawal */
DECLARE @Success BIT;
DECLARE @Message NVARCHAR(200);

EXEC dbo.sp_ProcessTransaction
    @AccountID = 1,
    @ToAccountID = NULL,
    @Amount = 75.00,
    @TransactionType = 'Withdrawal',
    @Success = @Success OUTPUT,
    @Message = @Message OUTPUT;

SELECT
    @Success AS Success,
    @Message AS Message;


/* Test Transfer */
declare @Success BIT;
declare @Message NVARCHAR(200);

EXEC dbo.sp_ProcessTransaction
	@AccountID = 1,
	@ToAccountID = 2,
	@TransactionType = 'Transfer',
	@Amount = 30.00,
	@Success = @Success OUTPUT,
	@Message = @Message OUTPUT;

SELECT
	@Success as Success,
	@Message as Message;


