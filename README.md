# Rykergogo - Ethical Hacking
## Huntress CTF Solutions!
<details markdown>
  <br>
  <summary>[Malware] Challenge Zerion Solution</summary>
  For this challenge, participants are provided with a file named <code>zerion</code>.<br><br>
  At first glance, the contents of this file reveals some PHP code.<br><br>
  <img src="https://i.imgur.com/vAJmHp2.png"><br><br>
  Digging in a little farther, there seems to be some encoded text at the end of the file.<br><br>
  <img src="https://i.imgur.com/pnB0T5D.png"><br><br>
  In the first screenshot, the variable <code>$L66Rgr</code> is being assigned to an array containing the php code and the base64 string at the end of the file.<br><br>
  Specifically, the explode function is splitting the current file by the string <code>?></code> which would isolate the base64 string into the second element of the array.
  The array should look similar to this:<br><br>
  
  `[php_code, base64_text]`<br><br>
  
  <img src="https://i.imgur.com/u0WLJKE.png"><br><br>
  A little further along the code is this variable `$L6CRgr`. Here, an array is created as so:<br><br>
  
  `[/x/i, x, base64_text]`<br><br>
  
  The first two arguments are just decoded base64 text. The third element is what we want to pay more attention to. It's doing some stuff to the second element of the array created before.<br><br>
  Following the function call, first run the third element of the array (base64 text at end of file) through a rot13 decoder.<br><br>
  <img src="https://i.imgur.com/MYvLDUF.png"><br><br>
  Then take the output and reverse the string.<br><br>
  <img src="https://i.imgur.com/tJnesuQ.png"><br><br>
  Then we get, surprise surprise, base64 text. Run that through a base64 decoder.<br><br>
  <img src="https://i.imgur.com/YxBvzRf.png"><br><br>
  Now we're getting somewhere...<br><br>
  <img src="https://i.imgur.com/UFND3UT.png"><br><br>
  After searching through more php code, the flag is captured!
</details>
<details>
  <br>
  <summary>[Forensics] Challenge Traffic Solution</summary>
  For this challenge, participants are provided with a file called <code>traffic.7z</code>.<br><br>
  After extracting the file, reveals a bunch of gzip files<br><br>
  <img src="https://i.imgur.com/0N4uQeJ.png"><br><br>
  The naming convention of the files suggests these are zeek logs. <a href="https://docs.zeek.org/en/master/script-reference/log-files.html" target="_blank">More Info</a><br><br>
  After extracting the gzip files, we can now spin up a database using <a href="https://github.com/activecm/rita" target="_blank">Rita</a><br><br>
  <img src="https://i.imgur.com/oxjtWe1.png"><br><br>
  <code>rita import . logs</code> will create a database including all the files in the present working directory and name it logs.<br><br>
  <img src="https://i.imgur.com/jfZONRr.png"><br><br>
  <code>rita show-beacons logs -H</code> will spit out some data to look at. We can already see some suspicious looking connections based on how many were made. However, this format is hard to read and doesn't really show much.<br><br>
  <img src="https://i.imgur.com/PPQ9RPI.png"><br><br>
  Running the command <code>rita html-report logs</code> will create an organized html report for us.<br><br>
  <img src="https://i.imgur.com/x07K0Gt.png"><br><br>
  Looking at the Beacons, there are several outgoing connections that seem to be repeated more than usual. Along with a score that is VERY close to 1, this raises some red flags. Even more so with the highlighted IP.<br><br>
  <img src="https://i.imgur.com/8xqe2rV.png"><br><br>
  Trying to access the IP directly reveals this is pointing to some github url. 104 connections being made to one github link? Something isn't right.<br><br>
  <img src="https://i.imgur.com/hFkSOxm.png"><br><br>
  Switching to the Beacons SNI page, and searching for any github urls we find a github pages link.<br><br>
  <img src="https://i.imgur.com/Pq72u3J.png"><br><br>
  Voilà! Flag is captured :-)
</details>
<details>
  <br>
  <summary>[Malware] Challenge Hot Off The Press Solution</summary>
  Participants are provided with a file <code>hot_off_the_press</code>. In the metadata of the file we see it's UHA compressed file.<br><br>
  <img src="https://i.imgur.com/Qyw8oZD.png"><br><br>
  <img src="https://i.imgur.com/KfrOOka.png"><br><br>
  Using <a href="https://sam.gleske.net/uharc/" target="_blank">UHARC Cmd</a> we can extract the files provided we give the supplied password <code>infected</code> found on the challenge site.<br><br>
  <img src="https://i.imgur.com/YQ5XU4B.png"><br><br>
  The extracted file seems to be a <code>.ps1</code> Powershell file.<br><br>
  Going inside the file, we see some gzip and base64 happening to a provided string that is being concatenated.<br><br>
  <img src="https://i.imgur.com/2gdDxKb.png"><br><br>
  Going to the end of the string, we see that the string is first being decompressed using <a href="https://www.gzip.org/" target="_blank">gzip</a>, then decoded using Base64.<br><br>
  Looking closer, there is the <code>-f</code> Powershell string format specifier with replacement happening with 'L' and 'E'. This will be important further along...<br><br>
  <img src="https://i.imgur.com/fpOB1F7.png"><br><br>
  Copying the string into a new file, we can start to clean it up and make sense of it. First, by removing all instances of <code>'+'</code> since it's purely Powershell code and has nothing to do with the actual string.<br><br>
  <img src="https://i.imgur.com/IlhFid0.png"><br><br>
  Next we can remove <code>'</code>. It's safe to assume it doesn't have anything to do with the string.<br><br>
  <img src="https://i.imgur.com/mreTC4e.png"><br><br>
  Remember the replacement with 'L' and 'E' mentioned before? Here it comes into play. There are several <code>{0}</code> and <code>{1}</code> placements throughout the string. Now, we can replace every <code>{0}</code> with L and every <code>{1}</code> with E.<br><br>
  <img src="https://i.imgur.com/z3QjLNX.png"><br><br>
  <img src="https://i.imgur.com/STlzFpx.png"><br><br>
  Following the function call of the original Powershell code, put the cleaned up string into a gzip decompressor.<br><br>
  <img src="https://i.imgur.com/aPfObPj.png"><br><br>
  We have some more powershell code, and from first glance there doesn't seem to be anything interesting.<br><br>
  <img src="https://i.imgur.com/0S71jd9.png"><br><br>
  Until we notice a very long Base64 string.<br><br>
  <img src="https://i.imgur.com/ZA6PQJf.png"><br><br>
  Just copy and paste the string into a Base64 decoder and the flag is captured!
  
  
  
  
</details>
