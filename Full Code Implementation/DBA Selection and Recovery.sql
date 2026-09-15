USE SmartBankDB;
GO

GRANT SELECT ON dbo.Staff TO DBA;
GRANT SELECT ON dbo.Staff_History TO DBA;

GRANT SELECT ON dbo.Customer TO DBA;
GRANT SELECT ON dbo.Customer_History TO DBA;

GRANT SELECT ON dbo.Account TO DBA;
GRANT SELECT ON dbo.Account_History TO DBA;

GRANT SELECT ON dbo.TransactionRecord TO DBA;
GRANT SELECT ON dbo.TransactionRecord_History TO DBA;

GO