@extends('layouts.app')

@section('content')
<div class="container">
<div class="content-block">
				<h1>Python SSH Client with Paramiko</h1>
				<time datetime="2017-04-10">April 10, 2017</time>
				<p>Here's a rough draft of my Python SSH client. I have plans to expand the functionality to include SFTP. Stay tuned for a server implementation as well.</p>
				<pre class="prettyprint">
import paramiko
import sys
import getpass
import argparse
import os
import socket
import ipaddress

try:
    import interactive
except ImportError:
    from . import interactive

def validate_ip(s):
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False

def authenticate(transport, username, key):
    try:
        transport.auth_publickey(username, key)
    except paramiko.BadAuthenticationType:
        print("***Key authentication not allowed by server.***")
    except paramiko.AuthenticationException:
        print("***Authentication failed.***")
    except paramiko.SSHException:
        print("***Network error.***")
    finally:
        return

def pass_authenticate():
    password = getpass.getpass(prompt="Please enter your password:", stream=None)
    tr.auth_password(user, password)  # add some exceptions

parser = argparse.ArgumentParser(description="Connect to an SSH server.")
parser.add_argument("destination", help="the IP address (or hostname, if you use the 'n' flag) of the computer that you would like to connect to")
parser.add_argument("-n", "--name", help="use a hostname for the destination", action="store_true")
parser.add_argument("-u", "--username", help="the username that you'd like to use to connect (defaults to the local user if not specified)")
parser.add_argument("-p", "--port", type=int, help="specify a port to connect to (defaults to 22 if not specified)")
parser.add_argument("-a", "--autoadd", help="automatically add the host key to your computer (make sure you trust this computer)", action="store_true")
parser.add_argument("-k", "--key", help="specify the path to the private key that you would like to use for authentication")
args = parser.parse_args()

addr = args.destination
name = args.name
keyPath = args.key
user = args.username
port = args.port
auto = args.autoadd
password = None

if name:
    try:
        ip = socket.gethostbyname(addr)
        addr = ip
    except socket.gaierror as e:
        if e.errno == -2:
            print("***Unable to resolve hostname '" + addr + "'.***")
        else:
            print("***Error: " + str(e) + "***")

        sys.exit()
    except socket.error as e:
        print("***Error: " + str(e) + "***")
        sys.exit()
else:
    if not validate_ip(addr):
        print("***Invalid IP address.***")
        sys.exit()

if not port:
    port = 22

if not user:
    user = getpass.getuser()

try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((addr, port))
except Exception as e:
    print("***Error: " + str(e) + "***")
    sys.exit()

try:
    tr = paramiko.Transport(sock)

    try:
        tr.start_client()
    except paramiko.SSHException:
        print("***Error negotiating with server.***")
        sys.exit(1)

    try:
        keys = paramiko.HostKeys(os.path.expanduser("~/.ssh/known_hosts"))
    except IOError:
        try:
            keys = paramiko.HostKeys(os.path.expanduser("~/.ssh/known_hosts"))
        except IOError:
            print("***Error opening host keys file.***")
            keys = {}

    servPubKey = tr.get_remote_server_key()

    if keys.check(addr, servPubKey):
        print("***Host is known. Attempting authentication.***")
    elif auto:
        keys.add(addr, servPubKey.get_name(), servPubKey)
        try:
            keys.save(os.path.expanduser("~/.ssh/known_hosts"))
        except IOError:
            print("***Could not save server key to known_hosts. Error writing to file.***")
    else:
        print("***Unknown server! If you trust the computer you are connecting to, try using the -a flag next time to connect.***")
        sys.exit()

    if keyPath:
        if not os.path.isabs(keyPath):
            keyPath = os.path.abspath(keyPath)

        keyType = input("Please specify the key type, (r)sa or (d)sa or (e)cdsa or any other key to pass: ")
        keyType.lower()

        try:
            if keyType == "r":
                try:
                    key = paramiko.RSAKey.from_private_key_file(keyPath)
                except paramiko.PasswordRequiredException:
                    keyPass = getpass.getpass(prompt="Password for RSA key: ")
                    key = paramiko.RSAKey.from_private_key_file(keyPath, keyPass)
            elif keyType == "d":
                try:
                    key = paramiko.DSSKey.from_private_key_file(keyPath)
                except paramiko.PasswordRequiredException:
                    keyPass = getpass.getpass(prompt="Password for DSA key: ")
                    key = paramiko.DSSKey.from_private_key_file(keyPath, keyPass)
            elif keyType == "e":
                try:
                    key = paramiko.ECDSAKey.from_private_key_file(keyPath)
                except paramiko.PasswordRequiredException:
                    keyPass = getpass.getpass(prompt="Password for ECDSA key: ")
                    key = paramiko.ECDSAKey.from_private_key_file(keyPath, keyPass)
            else:
                print("***Trying password authentication.***")
                pass_authenticate()
        except IOError:
            print("***Error reading the key file.***")
        except paramiko.SSHException:
            print("***Invalid key or password.***")
        else:
            if not tr.is_authenticated():
                authenticate(tr, user, key)

    else:
        try:
            sshAgent = paramiko.Agent()
        except paramiko.SSHException:
            print("***Failed to start SSH agent.***")
        else:
            priKeys = sshAgent.get_keys()

            if priKeys:
                for priKey in priKeys:
                    authenticate(tr, user, priKey)
                    if tr.is_authenticated():
                        break

            else:
                print("***Failed to authenticate using the private keys available to the SSH agent.***")
                print("***Please use the -k &lt;path&gt; parameter if you know the path to a specific key that you would like to try.***")

            sshAgent.close()

    if not tr.is_authenticated():
        print("***Trying password authentication.***")
        pass_authenticate()

    if tr.is_authenticated():
        channel = tr.open_session()
        channel.get_pty()
        channel.invoke_shell()

        print("***Strap in...Here we go!***\n")

        interactive.interactive_shell(channel)

    tr.close()

except Exception as e:
    print("***Failed: " + str(e) + "***")

    try:
        tr.close()
    except:
        pass

    sys.exit(1)
				</pre>
			</div>
			<div class="content-block">
				<h1>Kruskal's Minimum Spanning Tree on Hackerrank</h1>
				<time datetime="2017-04-08">April 8, 2017</time>
				<p>Below is my solution to a problem posed on the site Hackerrank. Given a graph of weighted undirected edges, write an algorithm that finds a minimum spanning tree. That is, find 'a subset of the edges that forms a tree that includes every vertex, where the total weight of all the edges in the tree is minimized' (Kruskal's Algorithm - Wikipedia). A complete outline of the problem can be found here: <a href='https://www.hackerrank.com/challenges/kruskalmstrsub'>Kruskal on Hackerrank</a>. The code below is written in Python.</p>
				<pre class="prettyprint">
N, M = map(int,raw_input().strip().split(' '))

data = []
edges = 0
weight = 0
parent = N * [-1] # initialize parent array

for i in range(M):
    line = raw_input()
    node1, node2, wt = line.split()
    line = [int(wt), int(node1), int(node2)]
    data.append(line)

data.sort()

def findParent(x):
    if parent[x - 1] != -1:
        return findParent(parent[x - 1])
    else:
        return x    
            
for i in data:
    if edges == N - 1:
        break

    x = findParent(i[1])
    y = findParent(i[2])
        
    if x == y: # they have the same parent
        continue
    else:
        parent[y - 1] = x
            
    edges += 1 
    weight = weight + i[0]
    
print weight
				</pre>
			</div>
			<div class="content-block">
				<h1>Make Your Life Easier with OfficetoPDF</h1>
				<time datetime="2016-05-09">May 9, 2016</time>
				<p>This cute little VBScript takes Office files (.doc, .xls, .msg, etc) and converts them to PDF. It will also convert any attachments, if any, that are attached to an Outlook .msg file. 
				Just change the input folder to point to the folder of Office files and also change the output folder to point to a location of your choosing. I will try to write it to C# when I have time and maybe create a nice little user interface. Enjoy and I hope it helps!</p>
				<pre class="prettyprint">
inputFolder = "C:\Users\makkerman\Desktop\email_attach"
outputFolder = "C:\Users\makkerman\Desktop\test"

Dim objFSO, BaseName, outlookApp, doc, PDFPath, attachments, subStr, attachPath, objExcel, objWorkbook, objPowerPoint, objSlideDeck
Set objFSO = CreateObject("Scripting.FileSystemObject")
Set outlookApp = CreateObject("Outlook.Application")
Set objFolder = objFSO.GetFolder(inputFolder)
Set files = objFolder.Files
Set wordapp = CreateObject("Word.application")
Set objExcel = CreateObject("Excel.Application")
Set objPowerPoint = CreateObject("PowerPoint.Application")

If Not(objFSO.FolderExists(outputFolder)) then
	objFSO.CreateFolder(outputFolder)
End If

If Not(objFSO.FolderExists(outputFolder & "\attachments that failed to convert")) then
	objFSO.CreateFolder(outputFolder & "\attachments that failed to convert")
End If

Set objFile = objFSO.CreateTextFile(outputFolder & "\" & "error.txt", True)

For Each x in files
	'extension = objFSO.getextensionname(x.Path)
	SelectCase x.Path
Next

wordapp.Quit
objExcel.Quit
objPowerPoint.Quit
objFile.Close
Set outlookApp = Nothing
Set objFile = Nothing
Set objFSO = Nothing

Function SelectCase(filePath)
	dim extension
	extension = LCase(objFSO.getextensionname(filePath))
	
	Select Case extension
		Case "msg" ConvertMsgToPDF filePath
		Case "mht","txt","htm","doc","docx" ConvertWordToPDF filePath
		Case "xls","xlsx","xlsm","xml","csv" ConvertExcelToPDF filePath
		Case "ppt","pptx" ConvertPowerPointToPDF filePath
		Case Else DisplayErrorInfo("Failed to convert file: " & filePath)
	End Select
End Function

Function ConvertMsgToPDF(filePath)
	BaseName = objFSO.GetBaseName(filePath)

	On Error Resume Next
	Set email = outlookApp.CreateItemFromTemplate(filePath)
	Set attachments = email.Attachments 'save any attachments
		
	If Err.Number <> 0 then
		DisplayErrorInfo("Failed to convert file: " & filePath)
	Else
		'save as html and then convert
		htmlPath = outputFolder & "\" & BaseName & ".html"
		email.saveas htmlPath, 5
		ConvertWordToPDF htmlPath
		objFSO.DeleteFile(outputFolder & "\" & objFSO.GetBaseName(filePath) & ".html")
		objFSO.DeleteFolder(outputFolder & "\" & objFSO.GetBaseName(filePath) & "_files")
		
		If attachments.Count > 0 then
			For Each attached in attachments
				'WScript.Echo attached.FileName
				attachPath = outputFolder & "\attachments that failed to convert\" & attached.FileName
				attached.SaveAsFile attachPath
				'extension = objFSO.getextensionname(outputFolder & "\" & attached.FileName)
				SelectCase attachPath
				
				If objFSO.FileExists(outputFolder & "\" & objFSO.GetBaseName(attachPath) & ".pdf") then
					objFSO.DeleteFile(attachPath)
				End If
			Next
		End If
	End if
End Function

Function ConvertWordToPDF(filePath)
	BaseName = objFSO.GetBaseName(filePath)
	
	On Error Resume Next
	Set doc = wordapp.documents.open(filePath)

	if Err.Number <> 0 then
		DisplayErrorInfo("Failed the open file: " & filePath)
		doc.close
	else
		PDFPath = outputFolder & "\" & BaseName & ".pdf" 'absolute path of the pdf to be created
		doc.saveas PDFPath,17
		doc.close
	end if
End Function

Function ConvertExcelToPDF(filePath)
	BaseName = objFSO.GetBaseName(filePath)
	
	On Error Resume Next
	Set objWorkbook = objExcel.Workbooks.Open(filePath)

	if Err.Number <> 0 then
		DisplayErrorInfo("Failed the open file: " & filePath)
		objWorkbook.Close FALSE
	else
		PDFPath = outputFolder & "\" & BaseName & ".pdf" 'absolute path of the pdf to be created
		objWorkbook.ExportAsFixedFormat 0, PDFPath, 0, TRUE, FALSE, , , FALSE
		objWorkbook.Close FALSE
	end if
End Function

Function ConvertPowerPointToPDF(filePath)
	BaseName = objFSO.GetBaseName(filePath)
	
	On Error Resume Next
	Set objSlideDeck = objPowerPoint.Presentations.Open(filePath, , , FALSE)

	if Err.Number <> 0 then
		DisplayErrorInfo("Failed the open file: " & filePath)
		objSlideDeck.Close
	else
		PDFPath = outputFolder & "\" & BaseName & ".pdf" 'absolute path of the pdf to be created
		objSlideDeck.SaveAs PDFPath, 32, True
		objSlideDeck.Close
	end if
End Function

Sub DisplayErrorInfo(message)
    strError = message & VbCrLf & VbCrLf &_
      "Error Number (dec) : " & Err.Number & VbCrLf & _
      "Error Number (hex) : &H" & Hex(Err.Number) & VbCrLf & _
      "Error Description  : " & Err.Description & VbCrLf & _
      "Error Source       : " & Err.Source
    Err.Clear
    objFile.WriteLine(strError)
End Sub
				</pre>
			</div>
			<div class="content-block">
				<h1>Power up with Powershell</h1>
				<time datetime="2016-05-02">May 2, 2016</time>
				<p>This script allows one to find out what software is installed on each computer in an Active Directory Organizational Unit (OU).
				Start by opening Powershell with administrator privileges and then import the Active Directory module:</p>
				<kbd>import-module ActiveDirectory</kbd>
				<p>Copy and paste the below script into Powershell. Follow this by assigning the computers in an OU to a variable (or you can skip this step and pipe them straight into the function):</p>
				<kbd>$computerNames = Get-ADComputer -SearchBase 'OU="Windows Computers",dc=myDomain,dc=Local' -Filter '*' -Properties Description</kbd>
				<p>Now pipe the variable into the function:</p>
				<kbd>$computerNames | Get-InstalledSoftware</kbd>
				<p>I've provided a few optional parameters: -file, -like, and -noCheck. Any combination of these parameters can be used. -file allows one to write the output out to a text file, -like allows you to search only for
				software whose name matches the like parameter (wildcards are accepted for this parameter). Finally, -noCheck skips the check that would prevent duplicate software entries from being listed as sometimes a key to a piece of software can be in more than one place.
				The plus side to this is that the script runs <strong>much</strong> faster than with noCheck left off. However, on the down side, you run the risk of having a few software
				entries being duplicated, albeit not many in my experience. Here's an example using all three parameters:</p>
				<kbd>$computerNames | Get-InstalledSoftware -file "C:\Users\makkerman\Desktop\output.txt" -like "*adobe*" -noCheck</kbd>
				<p>The above would list the software installed on each computer in the "Windows Computers" OU. In addition the the console, output would be written to "output.txt" on my Desktop.
				It would list only software that has "adobe" anywhere in its name. Finally, noCheck is enabled.</p> 
				<p>Let 'er rip.</p>
				<pre class="prettyprint">
Function Get-InstalledSoftware {
    Param(
    	[Parameter(
            Mandatory=$true,
            Position=0,
            ValueFromPipeline=$true
        )]
        [Object[]]$computers,
        [string]$file,
        [string]$like,
        [switch]$noCheck
    )
    
    Begin {
        
    }
    
    Process {
        if(-not($computers)) { Throw “You must supply at least one computer” }
        
        foreach($computer in $computers) {
            $computerName = $computer.Name

            if($computer.Description) {
                $computerDesc = $computer.Description
            }
            
            $reachable = Test-Connection -ComputerName $computerName -Count 2 -Quiet
            
            if($reachable) {
                $LMkeys = @()
                $userKeys = @()
                $sw_list = @()  

                try {
                    $usersHive = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('Users', $computerName) #open HKEY_USERS hive
                    
                    $LMHive = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $computerName) #open HKEY_LOCAL_MACHINE hive
                    
                    $userProfiles = $usersHive.GetSubKeyNames() #the subkeys of $usersHive are all of the profiles on the computer
                    
                    if($LMHive.OpenSubKey("Software\Microsoft\Windows\CurrentVersion\Uninstall")) { #if the key exists (it's there but I'm erring on the side of caution)
                        $LMkeys += "Software\Microsoft\Windows\CurrentVersion\Uninstall" #x64 software keys to look through
                    }
                    
                    if($LMHive.OpenSubKey("Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall")) { #if the key exists (it's there but I'm erring on the side of caution)
                        $LMkeys += "Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall" #x86 software keys to look through
                    } 
                    
                    foreach($profile in $userProfiles) {
                        if($usersHive.OpenSubKey("$profile\Software\Microsoft\Windows\CurrentVersion\Uninstall")) { #if the key exists
                            $userKeys += "$profile\Software\Microsoft\Windows\CurrentVersion\Uninstall" #add to list of profile-specific software keys to look through
                        }
                    }
                    
                    #loop through the LocalMachine keys
                    foreach($parentKey in $LMkeys) {
                        $childKeys = $LMHive.OpenSubKey($parentKey).GetSubKeyNames()
                        foreach($childKey in $childKeys) {
                            $SWkey = $LMHive.OpenSubKey("$parentKey\$childKey")
                            
                            if($SWkey.getvalue("displayname") -like "") {
                                continue #break this iteration of the loop if it's blank
                            }
                            
                            if($like) {
                                if(-Not($SWkey.getvalue("displayname") -like $like)) {
                                    continue #break this iteration of the loop if the name doesn't match the value you're searching for
                                }
                            }
                            
                            if($noCheck) {
                                if($SWkey.getvalue("displayname")) {
                                    $sw_list += (New-Object PSObject -Property @{
                                                            "Name" = $SWkey.getvalue("displayname")
                                                            "Version" = $SWkey.getvalue("DisplayVersion")
    				                            })                              
                                }
                            } else {
                                $inList = $false
                                foreach($obj in $sw_list) {
                                    if($obj.Name -eq $SWkey.getvalue("displayname") -and $obj.Version -eq $SWkey.getvalue("DisplayVersion")) {
                                        $inList = $true
                                        break
                                    }
                                }
                                
                                if($inList -eq $false) {
                                    $sw_list += (New-Object PSObject -Property @{
                                                            "Name" = $SWkey.getvalue("displayname")
                                                            "Version" = $SWkey.getvalue("DisplayVersion")
    				                            })
                                }
                            }
                        }
                    }
                    
                    #loop through the Users keys
                    foreach($parentKey in $userKeys) {
                        $childKeys = $usersHive.OpenSubKey($parentKey).GetSubKeyNames()
                        foreach($childKey in $childKeys) {
                            $SWkey = $usersHive.OpenSubKey("$parentKey\$childKey")
                            
                            if($SWkey.getvalue("displayname") -like "") {
                                continue #break this iteration of the loop if it's blank
                            }
                            
                            if($like) {
                                if(-Not($SWkey.getvalue("displayname") -like $like)) {
                                    continue #break this iteration of the loop if the name doesn't match the value you're searching for
                                }
                            }
                            
                            if($noCheck) {
                                if($SWkey.getvalue("displayname")) {
                                    $sw_list += (New-Object PSObject -Property @{
                                                            "Name" = $SWkey.getvalue("displayname")
                                                            "Version" = $SWkey.getvalue("DisplayVersion")
    				                            })                              
                                }
                            } else {
                                $inList = $false
                                foreach($obj in $sw_list) {
                                    if($obj.Name -eq $SWkey.getvalue("displayname") -and $obj.Version -eq $SWkey.getvalue("DisplayVersion")) {
                                        $inList = $true
                                        break
                                    }
                                }
                                
                                if($inList -eq $false) {
                                    $sw_list += (New-Object PSObject -Property @{
                                                            "Name" = $SWkey.getvalue("displayname")
                                                            "Version" = $SWkey.getvalue("DisplayVersion")
    				                            })
                                }
                            }
                        }
                    }
                    
                    if(-Not($sw_list.length -eq 0)) {
                    
                        $toWrite = "software installed on $computerName $computerDesc"
                        write-host $toWrite
                        write-host ("-" * $toWrite.length)
                        
                        if($file) {
                            $toWrite | out-file $file -Append
                            ("-" * $toWrite.length) | out-file $file -Append 
                        }
                        
                        foreach($item in $sw_list) {
                            $name = $item.Name
                            $version = $item.Version
                            write-host $name $version
                            
                            if($file) {
                                "$name $version" | out-file $file -Append
                            }
                        }
                        write-host "`r`n"
                        if($file) {
                            "`r`n" | out-file $file -Append
                        }
                    }
                    
                } catch {
                    write-host "unable to access registry for $computerName $computerDesc`r`n"
                    
                    if($file) {
                    "unable to access registry for $computerName $computerDesc`r`n" | out-file $file -Append
                    }
                }
            } else {
                write-host "unable to reach $computerName $computerDesc`r`n"
                    
                if($file) {
                "unable to reach $computerName $computerDesc`r`n" | out-file $file -Append
                }
            }
        }
    }
    
    End {
    
    }
}
			</pre>
			</div>
</div>
@endsection

@section('script')
    <script src="https://cdn.rawgit.com/google/code-prettify/master/loader/run_prettify.js"></script>
@endsection