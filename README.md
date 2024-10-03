# t0xodile's CORS Check
Permissive CORS vulnerabilities are trickier to detect than you might think. However, using this burp extension you can extend Burp's default CORS scan checks, and add extra functionality to burp, allowing you to detect and attempt to exploit trusted domain CORS bypasses. The ideas and detection methods in this tool all stem from the following resources and research. 

1. [Exploiting trust: Weaponizing permissive CORS configurations by Thomas Stacey](https://outpost24.com/blog/exploiting-permissive-cors-configurations/)
2. [Exploiting CORS misconfigurations for Bitcoins and bounties by James Kettle](https://portswigger.net/research/exploiting-cors-misconfigurations-for-bitcoins-and-bounties)
3. [Advanced CORS Exploitation Techniques by Corben Leo](https://corben.io/blog/18-6-16-advanced-cors-techniques)
4. [URL validation bypass cheat sheet by PortSwigger](https://portswigger.net/web-security/ssrf/url-validation-bypass-cheat-sheet)

To use, simply download the latest .jar file from the releases page, install the extention and run an active scan. You can also right-click any request in burp and open the trusted domain scanner in order to check for, and attempt to exploit, trusted domain CORS bypasses. 

To build it yourself run the following commands. You can find the build in the `build\libs` folder:
1. `git clone <repo-URL-here>`
2. `cd outpost24-cors-check`
3. `gradle build`
