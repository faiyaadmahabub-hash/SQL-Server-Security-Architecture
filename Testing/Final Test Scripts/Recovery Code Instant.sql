USE SmartBankDB;
GO

/*All Directories*/
select * from dbo.vw_StaffDirectory;


/*The Recover Step*/
/*Change time using system time for staff id*/
SELECT
    StaffID,
    StaffName,
    Phone,
    Branch,
    Salary,
    SysStartTime,
    SysEndTime
FROM dbo.Staff
FOR SYSTEM_TIME ALL
ORDER BY SysStartTime DESC;
GO


/*Recovery of the data*/
DECLARE @Success BIT,
        @Message NVARCHAR(200);

EXEC dbo.sp_RecoverStaff
    @StaffID = 5,
    @AsOfDateTime = '2026-09-14 14:09:52.5365978',
    @Success = @Success OUTPUT,
    @Message = @Message OUTPUT;

SELECT
    @Success AS Success,
    @Message AS Message;
GO

/*Checking history for Acccount changes*/
SELECT
    AccountID,
    CustomerID,
    AccountType,
    Balance,
    SysStartTime,
    SysEndTime
FROM dbo.Account
FOR SYSTEM_TIME ALL
WHERE AccountID = 1
ORDER BY SysStartTime DESC;
GO

/*Recovery of the data for account changes*/
DECLARE @Success BIT,
        @Message NVARCHAR(200);

EXEC dbo.sp_RecoverAccount
    @AccountID = 1,
    @AsOfDateTime = '2026-09-08 03:35:54.9644138',
    @Success = @Success OUTPUT,
    @Message = @Message OUTPUT;

SELECT
    @Success AS Success,
    @Message AS Message;
GO




SELECT*
    
FROM dbo.TransactionRecord
FOR SYSTEM_TIME ALL
ORDER BY SysStartTime DESC;
GO