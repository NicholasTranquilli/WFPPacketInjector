# WFPPacketInjector
## Intro
For the safety of your computer, please only run this driver in a virtual environment.

I recommend using my networking library (https://github.com/NicholasTranquilli/Networking-Lib) for the example client and server as this demo is already set up to work with it.

## Setup
Required: Windows virtual machine (driver only tested on Windows 11)

### FIRST-TIME SETUP ONLY:
ON HOST MACHINE:
 - Set-VMComPort "[VM_NAME_HERE]" 1 \\.\pipe\[CUSTOM_PIPE_NAME]

ON VIRTUAL MACHINE TERMINAL
 - Bcdedit.exe -set TESTSIGNING ON
 - Bcdedit.ext /debug on
 - Bcdedit.exe /dbgsettings serial debugport:1 baudrate:115200
 - sc.exe create [SERVICE_NAME] type= kernel binpath="[PATH_TO_PASTED_DEBUG_FOLDER]/[driver_name].sys"

### SETUP EVERY TIME:
WINDBG (x64) (HOST MACHINE):
 - Run as admin
 - file -> Kernel Debug -> COM
 - Check "Pipe" and "Reconnect"
 - port = \\.\pipe\[PIPE_NAME]

VISUAL STUDIO (HOST/DEVELOPMENT MACHINE):
 - Update code as needed
 - Copy x64/Debug binary folder into VM

VM:
 - sc.exe start [SERVICE_NAME]
 - sc.exe stop [SERVIEC_NAME]

*Results will be in WinDbg console if done properly*

## SOURCES AND CITATIONS (NAME, PROJECT, URL):
 - Microsoft, Windows-Driver-Samples, https://github.com/microsoft/Windows-driver-samples/
      - Contains some very useful demos on a variety of different drivers.
      - The WFP driver sample featuring packet injection was helpful.
 - Jared Wright, WFPStarterKit, https://github.com/JaredWright/WFPStarterKit/blob/master/
      - WFPStarterKit by JaredWright is an incredible source for learning about
      - Windows Filtering Platform and creating WFP Callout Drivers.

## ADDITIONAL NOTES:
This driver and source code is for educational purposes only and was created as a final project for Central Connecticut State University’s CS 492 course.
