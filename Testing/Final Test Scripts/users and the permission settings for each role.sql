USE master;
GO
/*Show all SQL Server Logins*/
SELECT 
    name AS LoginName,
    type_desc AS LoginType,
    create_date,
    default_database_name
FROM sys.server_principals
WHERE type IN ('S','U','G')
ORDER BY name;
GO



USE SmartBankDB;
GO
/*Show all Database Users*/
SELECT 
    name AS UserName,
    type_desc AS UserType,
    authentication_type_desc
FROM sys.database_principals
WHERE type IN ('S','U','G')
ORDER BY name;
GO


/*Show Users Assigned to Each Role*/
SELECT
    RoleName = R.name,
    MemberName = U.name
FROM sys.database_role_members RM
INNER JOIN sys.database_principals R
    ON RM.role_principal_id = R.principal_id
INNER JOIN sys.database_principals U
    ON RM.member_principal_id = U.principal_id
ORDER BY 
    R.name,
    U.name;
GO



/*Show Permission Settings for Each Role*/
SELECT
    PrincipalName = DP.name,
    PrincipalType = DP.type_desc,
    PermissionName = PER.permission_name,
    PermissionState = PER.state_desc,
    ObjectName = 
        CASE 
            WHEN PER.major_id = 0 THEN 'DATABASE'
            ELSE OBJECT_NAME(PER.major_id)
        END
FROM sys.database_permissions PER
INNER JOIN sys.database_principals DP
    ON PER.grantee_principal_id = DP.principal_id
ORDER BY
    DP.name,
    ObjectName,
    PermissionName;
GO




/*Show Effective Permissions for Each User*/
EXECUTE AS USER = 'Bank_Manager';

SELECT *
FROM fn_my_permissions(NULL, 'DATABASE');

REVERT;
GO



/*Show Complete Role + Permission Matrix (Best for Demo)*/
SELECT
    RoleName = R.name,
    PermissionType = P.permission_name,
    PermissionState = P.state_desc,
    ObjectName =
        CASE 
            WHEN P.major_id = 0 
            THEN 'DATABASE'
            ELSE OBJECT_NAME(P.major_id)
        END
FROM sys.database_role_members RM

INNER JOIN sys.database_principals R
    ON RM.role_principal_id = R.principal_id

LEFT JOIN sys.database_permissions P
    ON P.grantee_principal_id = R.principal_id

ORDER BY 
    R.name,
    ObjectName,
    PermissionType;
GO



/*Show Users + Roles + Permissions*/
SELECT
    UserName = U.name,
    RoleName = R.name,
    Permission = P.permission_name,
    PermissionState = P.state_desc,
    ObjectName =
        CASE
            WHEN P.major_id = 0 THEN 'DATABASE'
            ELSE OBJECT_NAME(P.major_id)
        END
FROM sys.database_role_members RM

INNER JOIN sys.database_principals R
    ON RM.role_principal_id = R.principal_id

INNER JOIN sys.database_principals U
    ON RM.member_principal_id = U.principal_id

LEFT JOIN sys.database_permissions P
    ON R.principal_id = P.grantee_principal_id

ORDER BY
    R.name,
    U.name,
    ObjectName;
GO