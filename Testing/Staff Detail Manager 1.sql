select * from dbo.vw_StaffDirectory

select * from dbo.vw_StaffOwnRecord
select * from dbo.vw_AllBankOfficers
select * from dbo.vw_CustomerAll
select * from dbo.vw_AccountAll

select * from dbo.vw_TransactionAll

CREATE TABLE dbo.Test_Manager_Table
(
    ID INT
);



/*Test to check Bank Manager updates staff details */
SELECT *
FROM dbo.vw_AllBankOfficers
where StaffID = 5;

DECLARE @Success BIT;
DECLARE @Message NVARCHAR(200);
EXEC dbo.sp_ManageStaff
    @StaffID = 5,
    @StaffName = 'Farah Aina',
    @Position = 'Bank Officer',
    @Branch = 'KL Branch',
    @Phone = '0199999999',
    @Salary = 4500,
    @IsActive = 1,
	@Success = @Success OUTPUT,
    @Message = @Message OUTPUT;

SELECT 
    @Success AS Success,
    @Message AS Message;

DECLARE @Success BIT;
DECLARE @Message NVARCHAR(200);
EXEC dbo.sp_ManageStaff
    @StaffID = 6,
    @StaffName = 'Ahmad Faizal',
    @Position = 'Bank Officer',
    @Branch = 'Ipoh Branch',
    @Phone = '0199999999',
    @Salary = 2500,
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

