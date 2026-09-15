/*Unmasking for DBA*/
USE SmartBankDB;
GO

GRANT UNMASK ON OBJECT::dbo.Account (Balance) TO DBA;
GO