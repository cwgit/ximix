echo off
IF NOT EXIST "%XIMIX_HOME%" (
	SET XIMIX_HOME=%~dp0..\
)

IF NOT EXIST "%XIMIX_HOME%\libs" (
	ECHO XIMIX_HOME is incorrect could not find XIMIX_HOME\libs
	goto END	
)

IF NOT EXIST "%JAVA_HOME%\bin\java.exe" (
	ECHO JAVA_HOME is not set, it must point to a valid java 1.7 installation.
	goto END
)

IF NOT EXIST "%XIMIX_HOME%/%1" (
	ECHO "NODE name has not been defined, eg: run.bat node1"
	goto END
)


"%JAVA_HOME%\bin\java.exe" -cp "%XIMIX_HOME%\libs\*" org.cryptoworkshop.ximix.node.Main "%XIMIX_HOME%\%1\conf\mixnet.xml" "%XIMIX_HOME%\%1\conf\node.xml"  

:END

