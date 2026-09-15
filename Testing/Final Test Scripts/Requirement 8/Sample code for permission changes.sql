USE master;
GO


/*Create Login credential*/
CREATE LOGIN SmartBank_DBA3
WITH PASSWORD = 'Dba3P@ss!',
CHECK_POLICY = OFF;
GO


/*Create database user*/
USE SmartBankDB;
GO

CREATE USER SmartBank_DBA3
FOR LOGIN SmartBank_DBA3;
GO


/*Add role into*/
ALTER ROLE DBA
ADD MEMBER SmartBank_DBA3;
GO


/*Verify role assignment*/
SELECT
    dp.name AS UserName,
    rp.name AS RoleName
FROM sys.database_role_members drm
JOIN sys.database_principals rp
    ON drm.role_principal_id = rp.principal_id
JOIN sys.database_principals dp
    ON drm.member_principal_id = dp.principal_id
WHERE dp.name = 'SmartBank_DBA3';
GO


/*Permission change*/
USE SmartBankDB;
GO

GRANT EXECUTE 
ON dbo.sp_ManageCustomer 
TO DBA;
GO


/*Revoke permission*/
REVOKE EXECUTE 
ON dbo.sp_ManageCustomer 
FROM DBA;
GO

