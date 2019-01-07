/*********************************
  FIND WEAK PASSWORDS SCRIPT

--Author: Shimon Gibraltar
--Email: shimongb@gmail.com

*********************************/

SET NOCOUNT ON

--Collect sql logins data
SELECT  NAME ,
        SUBSTRING(password_hash, 0, 3) Header ,
        CONVERT(VARBINARY(4), SUBSTRING(CONVERT(NVARCHAR(MAX), password_hash),
                                        2, 2)) Salt ,
        password_hash
INTO    #syslogin
FROM    sys.sql_logins

--Create password dictionary
CREATE TABLE #Password
    (
      PASSWORD NVARCHAR(255) NOT NULL
    )
GO

--Populate the table with data form: http://dazzlepod.com/site_media/txt/passwords.txt or any passwords list
INSERT  #Password
        SELECT  name
        FROM    #syslogin

--define the crypto algoritms to check
DECLARE @alg TABLE
    (
      Algoritm NVARCHAR(10) NOT NULL
    )
INSERT  @alg
        ( Algoritm )
VALUES  ( 'MD2' ),
        ( 'MD4' ),
        ( 'MD5' ),
        ( 'SHA' ),
        ( 'SHA1' ),
        ( 'SHA2_256' ),
		( 'SHA2_512' )

-->>> ����� and this is where the magic happens! ����� <<<---
SELECT  DISTINCT
        t.Name ,
        t.Algoritm ,
        t.ClearTextPassword ,
        t.OriginalPasswordHash ,
        t.salt
FROM    ( SELECT    SL.NAME ,
                    a.Algoritm ,
                    P.[Password] ClearTextPassword ,
                    sl.password_hash OriginalPasswordHash ,
                    sl.Header + sl.Salt + HASHBYTES(A.Algoritm,
                                                    P.[Password]
                                                    + CONVERT(NVARCHAR(MAX), sl.Salt)) MyHashedPassword ,
                    CONVERT(VARBINARY(4), SUBSTRING(CONVERT(NVARCHAR(MAX), sl.password_hash),
                                                    2, 2)) salt
          FROM      #syslogin SL
                    CROSS JOIN @alg A
                    CROSS JOIN #Password P
        ) t
WHERE   t.MyHashedPassword = t.OriginalPasswordHash

--cleaning up
IF OBJECT_ID('tempdb..#syslogin') IS NOT NULL 
    DROP TABLE #syslogin
IF OBJECT_ID('tempdb..##Password') IS NOT NULL 
    DROP TABLE #Password
IF OBJECT_ID('tempdb..#Password') IS NOT NULL 
    DROP TABLE #Password
