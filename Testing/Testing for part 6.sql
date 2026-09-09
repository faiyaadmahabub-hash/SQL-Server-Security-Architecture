SELECT
    database_name,
    backup_start_date,
    backup_finish_date,
    type,
	encryptor_type
FROM msdb.dbo.backupset
WHERE database_name = 'SmartBankDB'
ORDER BY backup_finish_date DESC;

USE master;
GO

SELECT 
    name,
    subject
FROM sys.certificates;


USE SmartBankDB;
GO

SELECT *
FROM dbo.Customer
WHERE CustomerID = 1;



