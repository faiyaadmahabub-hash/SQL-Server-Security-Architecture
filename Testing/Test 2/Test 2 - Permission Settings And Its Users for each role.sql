USE SmartBankDB;
GO

/* To show the users and roles */
SELECT
    r.name                        AS RoleName,
    m.name                        AS MemberName,
    m.type_desc                   AS MemberType,
    CASE WHEN l.is_disabled = 1 THEN 'DISABLED' ELSE 'ACTIVE' END AS LoginStatus
FROM sys.database_role_members drm
JOIN sys.database_principals r ON r.principal_id = drm.role_principal_id
JOIN sys.database_principals m ON m.principal_id = drm.member_principal_id
LEFT JOIN sys.sql_logins l     ON l.name        = m.name
WHERE r.name IN ('DBA', 'Bank_Manager', 'Bank_Officer', 'Customer', 'RecoveryAdmin')
ORDER BY r.name, m.name;
GO

/*To show the permission settings for each role*/
SELECT
    grantee.name AS PrincipalName,
    grantee.type_desc AS PrincipalType,
    permission.permission_name AS Permission,
    permission.state_desc AS PermissionState,
    OBJECT_NAME(permission.major_id) AS ObjectName
FROM sys.database_permissions permission
JOIN sys.database_principals grantee
    ON permission.grantee_principal_id = grantee.principal_id
ORDER BY 
    PrincipalName,
    ObjectName;
