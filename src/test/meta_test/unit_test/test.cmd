@ECHO OFF
SETLOCAL

SET TOP_DIR=%1
SET build_type=%2
SET "build_dir=%~3"

IF "%REPORT_DIR%" EQU "" SET REPORT_DIR=.
IF NOT EXIST "%REPORT_DIR%" MKDIR "%REPORT_DIR%"
IF EXIST core DEL /F /Q core
IF EXIST data\ RMDIR /S /Q data
IF EXIST meta_state.dump* DEL /F /Q meta_state.dump*
IF EXIST zoolog.log DEL /F /Q zoolog.log

SET "GTEST_OUTPUT=xml:%REPORT_DIR%\dsn.dist.service.meta.test.xml"
CALL "%build_type%\dsn.dist.service.meta.test.exe"
EXIT /B %ERRORLEVEL%
