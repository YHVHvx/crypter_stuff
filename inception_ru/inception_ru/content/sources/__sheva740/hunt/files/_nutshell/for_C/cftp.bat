rem @echo off
rem ****************************************************************************
rem 20051212 ShS
rem Командный файл для заливки файлов на FTP-сервер v 0.02
rem ======================= FTP variables
rem FTPUserName         - имя пользователя
rem FTPUserPassword     - пароль пользователя
rem FTPIPAddress        - IP-адрес FTP-сервера
rem LocalSourcePath     - локальная папка, которая содержит файлы для загрузки на FTP-сервер
rem FTPDestinationPath  - директория на FTP-сервере, куда будут загружены файлы
rem FTPCmdFileName      - путь к файлу с набором команд для загрузки файлов на FTP
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
rem ======================== Выкладываем файлы на FTP-сервер =================
rem ======================== подготовка файла с набором команд для FTP
    echo %FTPUserName%> %FTPCmdFileName%
    echo %FTPUserPassword%>>%FTPCmdFileName%
    echo cd %2>>%FTPCmdFileName%
    echo type binary>>%FTPCmdFileName%
    echo lcd %1>>%FTPCmdFileName%
    echo mput *.*>>%FTPCmdFileName%
    echo quit>>%FTPCmdFileName%
rem ======================== Выполняем подготовленный набор команд
    ftp -s:%FTPCmdFileName% -i %FTPIPAddress%
    del %FTPCmdFileName%
:END