select * from dbo.vw_StaffDirectory

select * from dbo.vw_StaffOwnRecord

CREATE TABLE dbo.Test_DBA_Table
(
    TestID INT PRIMARY KEY,
    TestName NVARCHAR(50)
);
GO


SELECT
    dp.name AS Principal,
    p.permission_name,
    p.state_desc
FROM sys.database_permissions p
JOIN sys.database_principals dp
ON p.grantee_principal_id = dp.principal_id
WHERE p.permission_name IN 
(
    'CREATE TABLE',
    'ALTER',
    'CONTROL'
)
ORDER BY dp.name;


SELECT
    event_time,
    action_id,
    server_principal_name,
    database_name,
    object_name,
    statement
FROM sys.fn_get_audit_file(
    'C:\SQLAudit\*.sqlaudit',
    DEFAULT,
    DEFAULT
)
WHERE statement LIKE 'CREATE TABLE%'
   OR statement LIKE 'CREATE TABLE %'
   OR statement LIKE 'ALTER TABLE%'
   OR statement LIKE 'DROP TABLE%'
ORDER BY event_time DESC;

Drop table dbo.Test_DBA_Table


/*Testing to check who has access to staff management procedures. */
SELECT 
    dp.name AS PrincipalName,
    o.name AS ObjectName,
    p.permission_name,
    p.state_desc
FROM sys.database_permissions p
JOIN sys.database_principals dp
ON p.grantee_principal_id = dp.principal_id
JOIN sys.objects o
ON p.major_id = o.object_id
WHERE o.name LIKE '%Staff%';

/*To test audit verification*/
SELECT *
FROM AuditSchema.AuditLog
WHERE TableName = 'Staff'
ORDER BY ChangeDate DESC;



/* To test Recovery of Staff update */
DECLARE @Success BIT;
DECLARE @Message NVARCHAR(200);

EXEC dbo.sp_RecoverStaff
    @StaffID = 5,
    @AsOfDateTime = '2026-09-07 08:21:42.7029878',
    @Success = @Success OUTPUT,
    @Message = @Message OUTPUT;

SELECT 
    @Success AS Success,
    @Message AS Message;

/*To test checking whether it has recovered or not */
Select * from  dbo.vw_Staff_History 
where StaffID = 5 
order by SysStartTime

SELECT *
FROM AuditSchema.AuditLog
WHERE TableName='Account'
ORDER BY ChangeDate DESC;





