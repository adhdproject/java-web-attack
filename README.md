# java-web-attack

**Original credit to Ethan. Forked and upgraded from his bitbucket :D**

This progam was heavily inspired by, and uses code from, the Social Engineering Toolkit.

https://www.trustedsec.com/social-engineer-toolkit/

Specifically, this project aims to break out the Java Applet Web Attack method from SET into a standalone tool. It was written in order to be used in the Active Defense Harbinger Distribution (ADHD), but can likely be used in other Ubuntu/Debian variants.

http://adhdproject.github.io

* clone.sh - Clones any web page and saves output to index.html.
* weaponize.py - Generates payloads using msfvenom for all 3 major OS's. You can customize the payload used for each operating system. You can even use a custom executable by replacing the appropriate file in the resulting output directory.g Reads in an html file and inserts Java applet tag into it. Also creates a Metasploit resource script to launch listeners for each of the payloads.
* serve.sh - Starts up a basic web server to use for delivering the payloads and cloned web page. Launches Metasploit using the generated resource script.
* applet.jar - The Java applet used in the web attack. It is signed by a legitimate code signing certificate.
* Java.java - The Java applet source code taken directly from SET. This is used to compile applet.jar.
* example_gmail.html - Example html page included to use in weaponizing.

Example usage:

```
./clone.sh https://gmail.com/
./weaponize.py index.html 127.0.0.1
./serve.sh
```
