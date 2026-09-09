/*Test Staff updates their own record*/
SELECT * FROM dbo.vw_StaffOwnRecord;

DECLARE @Success BIT;
DECLARE @Message NVARCHAR(200);

EXEC dbo.sp_UpdateOwnStaffRecord
    @Phone = '01875647389',
    @Success = @Success OUTPUT,
    @Message = @Message OUTPUT;

SELECT 
    @Success AS Success,
    @Message AS Message;

/*Test Recovery*/
/* From DBA */

/* Test if staff can update salary */
DECLARE @Success BIT;
DECLARE @Message NVARCHAR(200);

EXEC dbo.sp_UpdateOwnStaffRecord
    @Salary = 99999,
    @Success = @Success OUTPUT,
    @Message = @Message OUTPUT;

SELECT 
    @Success AS Success,
    @Message AS Message;

UPDATE dbo.vw_StaffOwnRecord
SET Salary = 99999
WHERE StaffID = 5;

SELECT Salary
FROM dbo.vw_StaffOwnRecord
WHERE StaffID = 5;


/* Test Staff tries updating another staff record (Supposedly not possible) */
DECLARE @Success BIT;
DECLARE @Message NVARCHAR(200);

EXEC dbo.sp_UpdateOwnStaffRecord
	@StaffID = 6,
    @Success = @Success OUTPUT,
    @Message = @Message OUTPUT;

SELECT 
    @Success AS Success,
    @Message AS Message;


/* Test Bank Officer cannot perform transactions */
DECLARE @Success BIT;
DECLARE @Message NVARCHAR(200);

EXEC dbo.sp_ProcessTransaction
    @AccountID = 1,
    @ToAccountID = NULL,
    @Amount = 100,
    @TransactionType = 'Deposit',
    @Success = @Success OUTPUT,
    @Message = @Message OUTPUT;