USE SmartBankDB;
GO

SELECT
    CustomerID,
    CustomerName,
    ICNumber
FROM dbo.Customer;
GO

EXEC dbo.sp_DecryptICNumber
    @CustomerID = 1;
GO

select * from dbo.vw_CustomerAll;