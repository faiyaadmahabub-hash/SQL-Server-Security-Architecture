/*Table Management*/

/*Create table*/
CREATE TABLE Security_Test
(
ID INT PRIMARY KEY,
Description VARCHAR(100)
);
GO

/* Add columns to tables */
ALTER TABLE Security_Test
ADD CreatedDate DATETIME;
GO

/*Modify column definition*/
ALTER TABLE Security_Test
ALTER COLUMN Description VARCHAR(200);
GO

/*Remove column*/
ALTER TABLE Security_Test
DROP COLUMN CreatedDate;
GO

/*Add constraints*/
ALTER TABLE Security_Test
ADD CONSTRAINT CK_Security_Test_ID
CHECK (ID > 0);
GO

/* Remove constraint */
ALTER TABLE Security_Test
DROP CONSTRAINT CK_Security_Test_ID;
GO

/*Create indexes*/
CREATE INDEX IX_Security_Test_Description
ON Security_Test(Description);
GO

/* Drop index */
DROP INDEX IX_Security_Test_Description
ON Security_Test;
GO

/*Rename table*/
EXEC sp_rename 
    'Security_Test',
    'Security_Test_Renamed';
GO

/*Check if rename is successful or not*/
SELECT name
FROM sys.tables
WHERE name LIKE 'Security%';

/*Refresh Intellisense in edit option then:*/

/*Drop table*/
DROP TABLE Security_Test;
GO