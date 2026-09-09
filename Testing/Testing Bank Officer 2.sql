select * from dbo.vw_StaffOwnRecord

select * from dbo.vw_AccountAll
select * from dbo.vw_TransactionAll

CREATE TABLE dbo.Test_Officer_Table
(
    ID INT
);


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


/* TESTING */
/* To test can execute customer account management operation  */
SELECT name
FROM sys.procedures
WHERE name LIKE '%Account%';


DECLARE @Success BIT;
DECLARE @Message NVARCHAR(200);

EXEC dbo.sp_ManageAccount
     @AccountID = 2,
	 @CustomerID = 2,
	 @AccountType = Savings,
	 @IsActive = 0,
     @Success = @Success OUTPUT,
     @Message = @Message OUTPUT;

SELECT 
    @Success AS Success,
    @Message AS Message;


SELECT *
FROM dbo.vw_AccountAll
WHERE AccountID = 2;





