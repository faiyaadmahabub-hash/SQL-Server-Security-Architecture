
SELECT * FROM dbo.vw_StaffOwnRecord;

/*Update */
DECLARE @Success BIT,
        @Message NVARCHAR(200);

EXEC dbo.sp_UpdateOwnStaffRecord
    @Phone = '0198888888',
    @Success = @Success OUTPUT,
    @Message = @Message OUTPUT;

SELECT
    @Success AS Success,
    @Message AS Message;
GO

SELECT * FROM dbo.vw_StaffOwnRecord;