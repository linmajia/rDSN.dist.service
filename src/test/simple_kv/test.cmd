@ECHO OFF
SETLOCAL EnableExtensions EnableDelayedExpansion

SET TOP_DIR=%1
SET build_type=%2
SET "build_dir=%~3"
SET "bin=.\%build_type%\dsn.dist.service.test.simple_kv.exe"
SET "cases="

IF NOT "%~4" EQU "" GOTO parse_args
IF NOT "%DSN_TEST_FILTER%" EQU "" (
    SET "filter=%DSN_TEST_FILTER:,= %"
    SET "filter=!filter::= !"
    FOR %%I IN (!filter!) DO CALL :add_case %%I
) ELSE (
    FOR %%F IN (case-*.act) DO (
        SET "name=%%~nF"
        CALL :add_case !name:~5,3!
    )
)
GOTO args_done

:parse_args
IF "%~4" EQU "" GOTO args_done
CALL :add_case %~4
SHIFT
GOTO parse_args

:args_done

FOR %%I IN (%cases%) DO (
    CALL :run_case %%I
    IF ERRORLEVEL 1 EXIT /B 1
    ECHO.
)

EXIT /B 0

:add_case
IF "%~1" EQU "" EXIT /B 0
ECHO ;%cases%; | FINDSTR /C:";%~1;" >NUL
IF ERRORLEVEL 1 SET "cases=%cases% %~1"
EXIT /B 0

:run_case
SET "id=%~1"

IF EXIST "case-%id%\test.cmd" (
    PUSHD "case-%id%"
    CALL test.cmd
    SET "ret=!ERRORLEVEL!"
    POPD
    EXIT /B !ret!
)

IF EXIST "case-%id%.act" (
    IF EXIST data\ RMDIR /S /Q data
    IF EXIST core* DEL /F /Q core*
    CALL :run_single case-%id%
    EXIT /B !ERRORLEVEL!
)

SET "found_subcase="
FOR %%F IN (case-%id%-?.act) DO (
    IF EXIST "%%F" (
        SET "found_subcase=true"
        IF EXIST data\ RMDIR /S /Q data
        IF EXIST core* DEL /F /Q core*
        CALL :run_single %%~nF
        IF ERRORLEVEL 1 EXIT /B 1
    )
)
IF DEFINED found_subcase EXIT /B 0

ECHO case-%id% not found
EXIT /B 1

:run_single
SET "prefix=%~1"
ECHO %bin% %prefix%.ini %prefix%.act
CALL "%bin%" "%prefix%.ini" "%prefix%.act"
SET "ret=%ERRORLEVEL%"

SET "log="
FOR /R %%L IN (log.1.txt) DO IF NOT DEFINED log IF EXIST "%%L" SET "log=%%L"
IF DEFINED log (
    FINDSTR /V /C:"FAILURE_DETECT" /C:"BEACON" /C:"beacon" /C:"THREAD_POOL_FD" "!log!" >"%prefix%.log"
    DEL /F /Q "!log!"
)

IF NOT "%ret%" EQU "0" (
    ECHO run %prefix% failed, return value = %ret%
)
EXIT /B %ret%
