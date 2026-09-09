SELECT *
FROM AuditSchema.AuditLog
WHERE TableName = 'Staff'
ORDER BY ChangeDate DESC;

SELECT *
FROM AuditSchema.AuditLog
WHERE TableName = 'TransactionRecord'
ORDER BY ChangeDate DESC;

Select * from  dbo.vw_Staff_History 
where StaffID = 6 
order by SysStartTime DESC

DECLARE @Success BIT;
DECLARE @Message NVARCHAR(200);

EXEC dbo.sp_RecoverStaff
    @StaffID = 6,
    @AsOfDateTime = '2026-09-07 08:21:42.7190465',
    @Success = @Success OUTPUT,
    @Message = @Message OUTPUT;

SELECT 
    @Success AS Success,
    @Message AS Message;

