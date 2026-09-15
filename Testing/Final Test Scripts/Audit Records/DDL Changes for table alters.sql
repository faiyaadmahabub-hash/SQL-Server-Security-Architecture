/*View Audit Records for DDL changes for whole tables*/
SELECT
    event_time,
    server_principal_name AS UserName,
    database_name,
    action_id,
    statement
FROM sys.fn_get_audit_file
(
    'C:\SQLAudit\*.sqlaudit',
    NULL,
    NULL
)
WHERE action_id IN ('SC','CR','AL','DR')
ORDER BY event_time DESC;
GO


/*DML audit query*/
/*Checks the changes inside of the tables for data insertion, deletion*/
SELECT TOP 20
    ChangedBy,
    TableName,
    ActionType,
    Activity,
    ChangeDate
FROM AuditSchema.AuditLog
WHERE TableName='Staff'
ORDER BY ChangeDate DESC;
GO


/*Account History Changes*/
SELECT *
FROM AuditSchema.AuditLog
WHERE TableName IN
(
    'Customer',
    'Account'
)
ORDER BY ChangeDate DESC;
GO


/*Staff Update own record*/
SELECT *
FROM AuditSchema.AuditLog
WHERE TableName='Staff'
AND RecordID='1'
ORDER BY ChangeDate DESC;
GO

/*Customer performs transaction*/
SELECT *
FROM AuditSchema.AuditLog
WHERE TableName='TransactionRecord'
ORDER BY ChangeDate DESC;
GO

/*Overall Changes*/
SELECT
    LogID,
    TableName,
    ColumnName,
    RecordID,
    Activity,
    ChangedBy,
    ActionType,
    ChangeDate
FROM AuditSchema.AuditLog
ORDER BY ChangeDate DESC;
GO


/*New User Audit Check*/
SELECT
    event_time,
    server_principal_name AS ChangedBy,
    statement
FROM sys.fn_get_audit_file
(
    'C:\SQLAudit\*.sqlaudit',
    NULL,
    NULL
)
WHERE statement LIKE '%SmartBank_DBA3%'
ORDER BY event_time DESC;
GO

