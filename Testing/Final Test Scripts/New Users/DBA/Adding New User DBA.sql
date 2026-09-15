USE SmartBankDB;
GO

/*Checking SmartBank user for DBA*/
SELECT 
    name,
    type_desc
FROM sys.database_principals
WHERE name = 'SmartBank_DBA3';
GO


/*New user*/
CREATE USER SmartBank_DBA3_Test WITHOUT LOGIN;
GO


/*Adding DBA3 as DBA role */
ALTER ROLE DBA
ADD MEMBER SmartBank_DBA3_Test;
GO


/*DBA role permission*/
GRANT SELECT
ON dbo.vw_CustomerAll
TO SmartBank_DBA3;
GO

/*Revoke Permission*/
REVOKE SELECT
ON dbo.vw_CustomerAll
FROM SmartBank_DBA3;
GO