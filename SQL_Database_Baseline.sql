USE SmartBankDB;  -- swap in your actual DB name
GO

ALTER AUTHORIZATION ON DATABASE::SmartBankDB TO sa;
GO

Create Database artBankDB;
GO
Use SmartBankDB;
GO




Create Table Staff(
 StaffID varchar(6) primary key,
 StaffName varchar(100),
 Position varchar(20),
 Branch varchar(50),
 Phone varchar(20),
 Salary decimal(10,2)
);

Create Table Customer(
 CustomerID varchar(6) primary key,
 CustomerName varchar(100),
 ICNumber varchar(20),
 Phone varchar(20),
 Address varchar(200)
);

Create Table Account(
 AccountID varchar(10) primary key,
 CustomerID varchar(6),
 AccountType varchar(20),
 Balance decimal(12,2)
);

Create Table TransactionRecord(
 TransID int identity primary key,
 AccountID varchar(10),
 TransDate datetime,
 Amount decimal(12,2),
 TransactionType varchar(20)
);