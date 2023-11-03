# Rykergogo - Ethical Hacking
## Huntress CTF Solutions!
### These are my solutions to Huntress challenges that I found to be the most fun.
<br>
<details markdown>
  <br>
  <summary>[Malware] Zerion Solution</summary>
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
  <summary>[Forensics] Traffic Solution</summary>
  <b>~~ NOTE: It's easier to complete this challenge within a Linux environment. ~~<br><br></b>
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
  <summary>[Malware] Hot Off The Press Solution</summary>
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
<details>
  <summary>[Forensics] Backdoored Splunk Solution</summary>
  For this challenge, participants are provided with a zip file containing some files used for Splunk Add-on for Windows.<br><br>
  <img src="https://i.imgur.com/lNbC6oe.png"><br><br>
  We want to direct our attention to the bin folder since these files were deemed suspicious. By viewing a certain powershell file within <code>bin/powershell/nt6-health.ps1</code> we can see a web request being made to the provided container on the challenge site.<br><br>
  <img src="https://i.imgur.com/t9eG782.png"><br><br>
  This web request includes an authorization header which is important to note... If we go to the challenge site we are met with this json message.<br><br>
  <img src="https://i.imgur.com/oHyw4Z2.png"><br><br>
  Now we can craft a HTTP GET request to the site adding in the authorization header with the value we found from the powershell file.<br><br>
  <img src="https://i.imgur.com/NG6ypYq.png"><br><br>
  You can use any tool you want to do this. Personally, I'm using <a href="https://www.postman.com/" target="_blank">Postman</a> because it's simple and gets the job done, but other tools like <a href="https://portswigger.net/burp/communitydownload" target="_blank">Burp Suite</a> should work fine.<br><br>
  <img src="https://i.imgur.com/ugyyO3i.png"><br><br>
  Once the request is sent, the server responds back with some Base64 encoded text inside a HTML comment.<br><br>
  <img src="https://i.imgur.com/kOpgJf7.png"><br><br>
  Decode the text using your favorite tool, and flag captured!
</details>
<details>
  <summary>[Misc.] Rock, Paper, Psychic Solution</summary>
  <br>
  Participants are provided with a 7zip archive which contains an exe file. Using DIE we can see it's a 64-bit exe file.<br><br>
  <img src="https://i.imgur.com/DHQGhPs.png"><br><br>
  <img src="https://i.imgur.com/n2EN0IO.png"><br><br>
  From the entropy analysis page, the binary seems to not be packed, which makes our job a lot easier.<br><br>
  <img src="https://i.imgur.com/VLP83uF.png"><br><br>
  Next open the binary in a dissassembler and begin to look for any interesting strings. I'm using <a href="https://hex-rays.com/ida-free/" target="_blank">IDA Freeware</a><br><br>
  <img src="https://i.imgur.com/QWPfcF3.png"><br><br>
  Here we can see several interesting strings that have to do with the gameplay along with some interesting Hex and seemingly random string of characters.<br><br>
  <img src="https://i.imgur.com/NPZOsXu.png"><br><br>
  Clicking into the Hex string, we see it's referenced in a function called <code>printFlag</code>.<br><br>
  <img src="https://i.imgur.com/TbAd2VE.png"><br><br>
  Searching through the function, it will lead you to a <code>fromRC4</code> function and then to a <code>genKeystream</code> function. Now we have an understanding that the flag is not hardcoded in the binary, rather it's generated at run time. To investigate further, we need a debugger.<br><br>
  <img src="https://i.imgur.com/wtbUMcI.png"><br><br>
  Before going further, take note of the address where <code>printFlag</code> is since we can try to trigger it during run time.<br><br>
  <img src="https://i.imgur.com/fLXDO0W.png"><br><br>
  Open the binary in a debugger of your choice, I'm using <a href="https://x64dbg.com/" target="_blank">x64dbg</a><br><br>
  <img src="https://i.imgur.com/s3J7v5k.png"><br><br>
  Run through the game, and the instruction will go to a different location in memory. We can exploit this by changing the next instruction to jump to the location of <code>printFlag</code> we saved earlier. Instruction should look similar to <code>jmp 0x4168F0</code>. Your address might be different.<br><br>
  <img src="https://i.imgur.com/gyxkfoj.png"><br><br>
  Continue with execution, and if done properly, flag should appear. Well done!
</details>
<details>
  <summary>[Misc.] PRESS PLAY ON TAPE Solution</summary>
  <br>
  This challenge is one of my personal favorites simply because of how unique it is.<br><br>
  Participants are provided with a wav file named <code>pressplayontape.wav</code>. Playing the audio file reveals an ear piercing sound, and a spectrogram reveals nothing.<br><br>
  <img src="https://i.imgur.com/P1HRlrN.png"><br><br>
  This requires us to think a little outside the box... Do a quick search on the filename and this will pop up.<br><br>
  <img src="https://i.imgur.com/m02sH4N.png"><br><br>
  Hmm.... Commodore 64. That's computer related, right? Turns out, Commodore 64 had it's own special audio file format with the extension <code>.tap</code> that could be used to hide messages and data when recorded from VHS tapes. So, now it's time to try to convert this <code>.wav</code> into <code>.tap</code>.<br><br>
  <img src="https://i.imgur.com/Fge62hj.png"><br><br>
  To accomplish this, I'm using <a href="https://commodore.software/downloads/download/160-tape-related-utilities/974-c64-tape-decode-v0-1" target="_blank">C64 Tape Decode</a>. Specifically, <code>wav2tap.exe</code>. Now we have the raw Tape data.<br><br>
  <img src="https://i.imgur.com/TybDqAq.png"><br><br>
  We can now take this data and save it into a tap file. I've named it <code>output.tap</code>.<br><br>
  <img src="https://i.imgur.com/oo0yaRd.png"><br><br>
  Here, I'm using a tap analysis tool <a href="https://commodore.software/downloads/download/160-tape-related-utilities/14125-tapex-v1-6" target="_blank">TapEx</a> to analyze <code>output.tap</code>. Another tool from commodore.software. Going to the View tab we see several sections. The section that looks the most interesting seems to be the <code>CBM DATA FIRST</code>. It contains some hex.<br><br>
  <img src="https://i.imgur.com/5H4pGMK.png"><br><br>
  Pop this hex into an online tool and convert to ascii, and there's the flag!
</details>
<details>
  <summary>[Forensics] Texas Chainsaw Massacre: Tokyo Drift Solution</summary>
  <br>
  This challenge is difficult and therefore one of my favorites.<br><br>
  Participants are provided with a Windows Event Log named <code>Application Logs.evtx</code>.<br><br>
  <img src="https://i.imgur.com/R7AuC4a.png"><br><br>
  Viewing this file with the built in Windows Event Viewer, not much can be found from the log alone.<br><br>
  <img src="https://i.imgur.com/YoCUk0m.png"><br><br>
  If we take a look at the event log, there is some interesting obfuscated text planted in the file here.<br><br>
  <img src="https://i.imgur.com/d1JKe0n.png"><br><br>
  This text is obfuscated powershell code, so we can edit it. Remove the last statement to print it separately and run the script. Now we have our first stage of deobfuscation.<br><br>
  <img src="https://i.imgur.com/ccoUGvt.png"><br><br>
  Copy the output and modify it so the first statement is on a separate line. Make additional edits as needed and run, and now we have something that is starting to look like recognizable code. This task is all about trial and error...<br><br>
  <img src="https://i.imgur.com/2XtazI6.png"><br><br>
  You know the drill, copy the output and make modifications as necessary to get it to run properly. However, this time, it's not spitting anything out. Hmm... We need to try something else.<br><br>
  <img src="https://i.imgur.com/NCNwjZT.png"><br><br>
  Maybe it's nothing we're doing wrong, the code just isn't supposed to print anything at this stage. So we force it to print output with <code>Write-Output $output</code>. With <code>$output</code> assigned to the code.<br><br>
  <img src="https://i.imgur.com/P8ERqxQ.png"><br><br>
  Taking the output from the previous run, copy that output and format it so it spits out the result. Your code should look similar to mine, and now we run and get something that looks like pure Powershell code. Now we're close.<br><br>
  <img src="https://i.imgur.com/ggW3lIF.png"><br><br>
  Looking closer at the output from the previous run, the code seems to be trying to get some data from the Dns Name <code>eventlog.zip</code>.<br><br>
  <img src="https://i.imgur.com/GBeWKsk.png"><br><br>
  We also notice the data taken from the remote server is being decoded from base64 and converted into a readable string. We can force this to run by taking the code out of the try catch block and just running it independently on the next line.<br><br>
  <img src="https://i.imgur.com/Pz13vbd.png"><br><br>
  Run that code, and flag is down!<br><br>
  NOTE: This challenge is based off a fairly recent attack which involves hiding shellcode in Windows Event Logs. More info <a href="https://www.bleepingcomputer.com/news/security/hackers-are-now-hiding-malware-in-windows-event-logs/">here</a>.
</details>
<details>
  <summary>[Malware] Speakfriend Solution</summary>
  <br>
  Participants are provided with a 7zip archive named <code>main.7z</code>. Within this archive is a main file which seems to be an <code>ELF</code> file.<br><br>
  <img src="https://i.imgur.com/4TOPncn.png"><br><br>
  <img src="https://i.imgur.com/lSw4zsA.png"><br><br>
  We can use <a href="https://ghidra-sre.org/" target="_blank">Ghidra</a> to dissassemble the file and we can already see some weird Hex in the main function.<br><br>
  <img src="https://i.imgur.com/xy1O0s4.png"><br><br>
  Take the hex and convert to Ascii, and you get a string that's reversed. By reversing the string again, we get something that looks meaningful. Take note of this string it will be important later.<br><br>
  <img src="https://i.imgur.com/dtTmSse.png"><br><br>
  If we notice the response from a simple GET request to the container, there is a header <code>User-Agent</code> that looks very similar to the string we just extracted from the <code>main.elf</code>.<br><br>
  <img src="https://i.imgur.com/EY5SjCL.png"><br><br>
  Make a GET request to the container again, but this time replace the <code>User-Agent</code> header with the string we extracted from the main file. The response we get is a link to somewhere else on the server.<br><br>
  <img src="https://i.imgur.com/KUiZfRh.png"><br><br>
  Make a GET request to the provided url, and you win!
</details>
<details>
  <summary>[Malware] RAT Solution</summary>
  <br>
  Participants are provided with a 7zip archive named <code>rat.7z</code>. Extracting the archive reveals a file <code>rat</code>.<br><br>
  <img src="https://i.imgur.com/wCpYqjb.png"><br><br>
  This file has the "MZ" signature which indicates a PE (Portable Executable). Now it's time to analyze this further within a virtual environment.<br><br>
  <img src="https://i.imgur.com/K0flyqC.png"><br><br>
  <a href="https://github.com/horsicq/DIE-engine" target="_blank">Detect It Easy</a> indicates this is a .NET 64 Bit exe file.<br><br>
  <img src="https://i.imgur.com/FhLq2qD.png"><br><br>
  It's always good to check entropy to see if it needs unpacking. All indications point to not being packed which makes the job easier.<br><br>
  <img src="https://i.imgur.com/oBWrJ0X.png"><br><br>
  Here, we can use a .NET dissassembler and debugger <a href="https://github.com/dnSpy/dnSpy" target="_blank">dnSpy</a> to take a look inside the code. There's a decrypt function that's worth looking at.<br><br>
  <img src="https://i.imgur.com/m3K3T7X.png"><br><br>
  If we place a breakpoint on the return array after decrypting and run, we get an array with the magic bytes signature <code>4D 5A</code>. This indicates it's decrypting and probably going to try to execute the PE file contained within the array.<br><br>
  <img src="https://i.imgur.com/IqcxCW0.png"><br><br>
  We can view the array in a Memory Map and dump the selection to a file to analyze this file further.<br><br>
  <img src="https://i.imgur.com/4XkMvVL.png"><br><br>
  Using DIE, this file seems to be a .NET 32 Bit exe.<br><br>
  <img src="https://i.imgur.com/FGDLjc9.png"><br><br>
  This file seems to also not be packed.<br><br>
  <img src="https://i.imgur.com/S7DxlGQ.png"><br><br>
  Using dnSpy again, this file seems to be the actual RAT that will attempt to spin up a reverse shell (Client.Helper probably) along with applying some features in Settings.<br><br>
  <img src="https://i.imgur.com/Z2wy09T.png"><br><br>
  Going into Settings, there's more decryption going on that seems to be getting the settings for the stub. This will be important in a little bit...<br><br>
  <img src="https://i.imgur.com/DDlxNmM.png"><br><br>
  Scrolling down we notice a string <code>Flag</code> that isn't used by any code present in the file. Copy this string down as we'll use it.<br><br>
  <img src="https://i.imgur.com/eyIcjAz.png"><br><br>
  What we can do now is place a breakpoint on the return statement in <code>Decrypt</code> and replace the input with the string we just copied down.<br><br>
  <img src="https://i.imgur.com/bC47XN6.png"><br><br>
  Step over the return statement to view the return value, and nice job! We took down the RAT.
</details>
<details>
  <summary>[Malware] Batchfuscation Solution</summary>
  <br>
  Participants are provided with a file <code>batchfuscation</code> and upon inspection, it's a batch script.<br><br>
  <img src="https://i.imgur.com/XxfbwZa.png"><br><br>
  <img src="https://i.imgur.com/jbegCcX.png"><br><br>
  To print the output of the script into a text file, we can add this code to the top of the file and run it.<br><br>
  <img src="https://i.imgur.com/9wZi2YK.png"><br><br>
  The output prints something like this, and we can notice some replacement going on with the alphabet, numbers, and some special characters.<br><br>
  <img src="https://i.imgur.com/C4Ydxo2.png"><br><br>
  Using the replacement provided, we can craft the word <code>flag</code>. We need to include <code>%%</code> as we'll be searching for it in the script.<br><br>
  <img src="https://i.imgur.com/SrQxLCM.png"><br><br>
  Searching for this word, we find several instances. It looks like <code>flag</code> is apart of some sentences here, and looking closer each sentence <code>flag</code> is apart of, starts the same. Let's print this out during runtime and log it.<br><br>
  <img src="https://i.imgur.com/oyq0AP9.png"><br><br>
  Copy the entire sentence including <code>flag</code> and replace with <code>echo + (sentence + flag)</code> as shown.<br><br>
  <img src="https://i.imgur.com/vZ69kQC.png"><br><br>
  After running the script again, the log will now show the characters of the flag indexed from 1 to 37 (including <code>flag{}</code>). We basically have the flag, now it's just a matter of magic string formatting.<br><br>
  <img src="https://i.imgur.com/Ol9MMeA.png"><br><br>
  We can narrow the text down to just the flag characters by using a regex expression.<br><br>
  <img src="https://i.imgur.com/M3rdfJP.png"><br><br>
  At this point, use whatever methods and tools you want to format the string further to piece together the flag. For example, I just stripped the text down to the <code>(index)=(flag_character)</code> and semi-ordered by the index to make it easier to piece together.<br><br>
</details>
<details>
  <summary>[Forensics] Tragedy Redux</summary>
  <br>
  <img src="https://i.imgur.com/6T1egNK.png"><br><br>
  Participants are provided with a 7zip file containing a file <code>tragedy_redux</code>. Upon inspection it has a magic bytes signature that doesn't signify any known file type.<br><br>
  <img src="https://i.imgur.com/wRYTAIo.png"><br><br>
  Looking through the contents of the file for clues to it's type, it has a <code>word/vbaProject.bin</code> which means it's likely a word document with macro(s).<br><br>
  <img src="https://i.imgur.com/ya388zG.png"><br><br>
  The magic bytes signature for word documents is <code>50 4B 03 04</code>, so we can overwrite the previous incorrect signature. <a href="https://en.wikipedia.org/wiki/List_of_file_signatures">List of file signatures</a>.<br><br>
  <img src="https://i.imgur.com/LdzBREr.png"><br><br>
  Opening the file in Microsoft Word or any software that can handle word documents, reveals a page with the dictionary definition of tragedy.<br><br>
  <img src="https://i.imgur.com/tFXfhDo.png"><br><br>
  Checking the macros in the document we see some interesting VB code that's jumping through hoops to decode a string. You can sit and manually step through the code yourself, but I think it's best to run this and see what the output string is.<br><br>
  <img src="https://i.imgur.com/nrJgGxX.png"><br><br>
  Now, we can take this code and modify as needed to fit the VB program we're going to run. We can also remove the <code>If ActiveDocument.Name</code> snippet as this isn't going to be triggered in a word document.<br><br>
  <img src="https://i.imgur.com/PWoPAFB.png"><br><br>
  Running the code reveals a Base64 encoded string.<br><br>
  <img src="https://i.imgur.com/yL47CLI.png"><br><br>
  Decode the message using a Base64 decoder. Nice work!<br><br>
</details>
