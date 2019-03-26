**Microsoft Office Memory Corruption Vulnerability**

**CVE-2017-11882**

March 25, 2019
Shannon and Iman

**Outline**
-   Background
-   Vulnerability
-   How does it work?
-   Uses
-   Violations
-   How was it fixed? (solutions)
-   What the patch does
-   Example
 
**Background**

The code for Equation Editor was compiled in 2000 and was used in subsequent
versions of Word. It is run as a separate process and an attacker can send
separate commands thus taking advantage of the buffer overflow.

The affected Microsoft Office editions are:
-   Microsoft Office 2007 Service Pack 3
-   Microsoft Office 2010 Service Pack 2
-   Microsoft Office 2013 Service Pack 1
-   Microsoft Office 2016

![image](https://user-images.githubusercontent.com/48844366/54880979-e2f76300-4e29-11e9-8f59-73383f260895.png)

**CVE Severity Level**

**Vulnerability**

This is a vulnerability that allows an attacker to remotely execute malicious
code by exploiting a weakness in Microsoft Word Equation Editor.   The objective is for the user to click on a ‘trusted’ link or attachment. For example, an attacker creates an attachment (e.g. fake invoice).  When the user opens the attachment, the malicious code is inserted via Equation Editor and then it runs under the current user’s permission.

Shown below is the Equation Editor in Word:

![image](https://user-images.githubusercontent.com/48844366/54880987-f7d3f680-4e29-11e9-9ccc-1fbd3a3e3c55.png)

**How Does it Work?**

An attachment or link is sent to a user. The user believes it is valid and opens
the link or attachment. However, malicious code is contained in the link or
attachment. when the user opens the attachment or clicks on the link, the code
overflows the buffer and takes advantage of the Equation Editor to run commands
and/or insert malicious code.

**Uses**

The attacker can include any code or command. For example, directing to a
different ip address, gaining access to sensitive information, changing data or
making the system unusable.

**Violations**

Exploiting this vulnerability, the attacker can violate confidentiality,
integrity and availability of service. Confidentiality can be compromised if the
attacker gains access to sensitive data. Integrity can be compromised because
the attacker is able to modify the data. Availability can be comprised if the
attacker changes the code so that it is an infinite loop and/or corrupting
memory so that the system becomes unavailable.

**Solutions**

If unable to download or apply the patch, one can disable Equation Editor in the
registry. With this option, it is important to make a backup prior to this
procedure. It is always a good idea to make backups on a regular basis. And of
course do not download unknown files!


**What the patch does**

This function takes a pointer to the destination buffer and copies characters,
one by one in a loop, from user-supplied string to this buffer. It is also the
very function that Embedi found to be vulnerable in their research; namely,
there was no check whether the destination buffer was large enough for the
user-supplied string, and a too-long font name provided through the Equation
object could cause a buffer overflow.  
Microsoft's fix introduced an additional parameter to this function, specifying
the destination buffer length. The original logic of the character-copying loop
was then modified so that the loop ends not only when the source string end is
reached, but also when the destination buffer length is reached - preventing
buffer overflow. In addition, the copied string in the destination buffer is
zero-terminated after copying, in case the destination buffer length was reached
(which would leave the string unterminated).  


![image](https://user-images.githubusercontent.com/48844366/54881004-19cd7900-4e2a-11e9-8027-5a7706654f28.png)

**Example:**
Code folder holds an .rtf file which exploits CVE-2017-11882 vulnerability and
runs calculator in the system.

![image](https://user-images.githubusercontent.com/48844366/54881012-323d9380-4e2a-11e9-8727-015bcda46e68.png)

![image](https://user-images.githubusercontent.com/48844366/54881029-45e8fa00-4e2a-11e9-9011-e8de167ff464.png)

![image](https://user-images.githubusercontent.com/48844366/54881061-919ba380-4e2a-11e9-92da-78703b8925b3.png)


**References**
-   <https://nvd.nist.gov/vuln/detail/CVE-2017-11882#vulnCurrentDescriptionTitle>
-   <http://cwe.mitre.org/data/definitions/119.html>
-   <https://www.rapid7.com/db/vulnerabilities/msft-cve-2017-11882>
-   <https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-11882>
-   <https://www.youtube.com/watch?v=aBWAHxpXHEk>
-   <https://unit42.paloaltonetworks.com/unit42-analysis-of-cve-2017-11882-exploit-in-the-wild/>
-   <https://github.com/embedi/CVE-2017-11882>
-   <https://twitter.com/search?f=tweets&q=CVE-2017-11882>
-   <https://blog.0patch.com/2017/11/did-microsoft-just-manually-patch-their.html>
