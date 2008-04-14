'================================================================================
'ImportPfx.vbs
'
'Copyright ©2008 Liam Kirton <liam@int3.ws>
'================================================================================

Function InstallCapicom()
	For i = 0 To 1
		On Error Resume Next
		Set Store = CreateObject("CAPICOM.Store")
		
		If Err.Number <> 0 Then
			InstallCapicom = False
			
			On Error Goto 0
			Set Shell = CreateObject("WScript.Shell")
			Set Regsvr32Exec = Shell.Exec("Regsvr32 /s Capicom.dll")
			Do While Regsvr32Exec.Status = 0
				WScript.Sleep 100
			Loop
		Else
			InstallCapicom = True
		
			Store.Close
			Exit Function
		End If
	Next
End Function

'================================================================================

Sub InstallPfx()
	On Error Goto 0

	Const CAPICOM_KEY_STORAGE_EXPORTABLE = 1
	Const CAPICOM_LOCAL_MACHINE_KEY = 1
	Const CAPICOM_LOCAL_MACHINE_STORE = 1
	Const CAPICOM_STORE_OPEN_READ_WRITE = 1
	Const CAPICOM_STORE_OPEN_EXISTING_ONLY = 128
	
	Dim Store
	Dim Certificate
	
	Set Store = CreateObject("CAPICOM.Store")
	Store.Open CAPICOM_LOCAL_MACHINE_STORE, "My", CAPICOM_STORE_OPEN_READ_WRITE or CAPICOM_STORE_OPEN_EXISTING_ONLY
	
	Set Certificate = CreateObject("CAPICOM.Certificate")
	Certificate.Load "SslCatRoot.pfx", "SslCat", CAPICOM_KEY_STORAGE_EXPORTABLE, CAPICOM_LOCAL_MACHINE_KEY
	Store.Add Certificate
	
	Set Certificate = CreateObject("CAPICOM.Certificate")
	Certificate.Load "SslCat.pfx", "SslCat", CAPICOM_KEY_STORAGE_EXPORTABLE, CAPICOM_LOCAL_MACHINE_KEY
	Store.Add Certificate
	
	Store.Close
End Sub

'================================================================================

If InstallCapicom() = True Then
	InstallPfx()
Else
	WScript.Echo "ImportPfx.vbs Error: CAPICOM Installation Failed."
End If

'================================================================================