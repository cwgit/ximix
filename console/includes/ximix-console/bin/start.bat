echo off
IF NOT EXIST "%XIMIX_CONSOLE_HOME%" (
	SET XIMIX_CONSOLE_HOME=%~dp0..\
)

IF NOT EXIST "%XIMIX_CONSOLE_HOME%\libs" (
	ECHO XIMIX_CONSOLE_HOME is incorrect could not find XIMIX_CONSOLE_HOME\libs
	goto END	
)

IF NOT EXIST "%JAVA_HOME%\bin\java.exe" (
	ECHO JAVA_HOME is not set, it must point to a valid java 1.7 installation.
	goto END
)


"%JAVA_HOME%\bin\java.exe" -cp "%XIMIX_CONSOLE_HOME%\libs\*" org.cryptoworkshop.ximix.console.Main %2 %1"

:END

