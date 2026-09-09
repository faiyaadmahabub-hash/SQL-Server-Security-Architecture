SELECT
    database_name,
    backup_start_date,
    backup_finish_date,
    type,
	encryptor_type
FROM msdb.dbo.backupset
WHERE database_name = 'SmartBankDB'
ORDER BY backup_finish_date DESC;

SELECT *
FROM dbo.Customer
WHERE CustomerID = 1;

/* To check whether number 8 can perform some permission changes to the roles */
SELECT 
USER_NAME() AS CurrentUser,
IS_MEMBER('DBA') AS IsDBA;

SELECT 
    dp.name AS UserName,
    rp.name AS RoleName
FROM sys.database_role_members drm
JOIN sys.database_principals rp
ON drm.role_principal_id = rp.principal_id
JOIN sys.database_principals dp
ON drm.member_principal_id = dp.principal_id;

/* Give Bank Officers permission to view a test table. */
CREATE TABLE dbo.Audit_Test_Table
(
    TestID INT PRIMARY KEY,
    TestName VARCHAR(50)
);

INSERT INTO dbo.Audit_Test_Table
VALUES
(1,'Permission Test');
GO

GRANT SELECT
ON dbo.Audit_Test_Table
TO Bank_Officer;
GO




