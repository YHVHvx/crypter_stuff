rem @echo off
rem ****************************************************************************
rem 20051212 ShS
rem ��������� ���� ��� ������� ������ �� FTP-������ v 0.02
rem ======================= FTP variables
rem FTPUserName         - ��� ������������
rem FTPUserPassword     - ������ ������������
rem FTPIPAddress        - IP-����� FTP-�������
rem LocalSourcePath     - ��������� �����, ������� �������� ����� ��� �������� �� FTP-������
rem FTPDestinationPath  - ���������� �� FTP-�������, ���� ����� ��������� �����
rem FTPCmdFileName      - ���� � ����� � ������� ������ ��� �������� ������ �� FTP
rem @echo on
    echo Usage:
    echo           cftp.bat source_folder  destinatoin_ftp_folder

    if %1=="" goto END
    if %2=="" goto END
rem
    set FTPUserName=anonymous
    set FTPUserPassword=IE40user@
    set FTPIPAddress=192.168.1.1
    set FTPCmdFileName=.\FTPcommands.txt
rem ==========================================================================
rem ======================== ����������� ����� �� FTP-������ =================
rem ======================== ���������� ����� � ������� ������ ��� FTP
    echo %FTPUserName%> %FTPCmdFileName%
    echo %FTPUserPassword%>>%FTPCmdFileName%
    echo cd %2>>%FTPCmdFileName%
    echo type binary>>%FTPCmdFileName%
    echo lcd %1>>%FTPCmdFileName%
    echo mput *.*>>%FTPCmdFileName%
    echo quit>>%FTPCmdFileName%
rem ======================== ��������� �������������� ����� ������
    ftp -s:%FTPCmdFileName% -i %FTPIPAddress%
    del %FTPCmdFileName%
:END