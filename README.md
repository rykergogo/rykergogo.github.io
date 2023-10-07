# Rykergogo - Ethical Hacking
## Huntress CTF Solutions!
<details markdown>
  <br>
  <summary>Challenge Zerion Solution</summary>
  For this challenge, participants are provided with a file named `zerion`.<br>
  At first glance, the contents of this file reveals some PHP code.<br>
  <img src="https://i.imgur.com/vAJmHp2.png"><br>
  Digging in a little farther, there seems to be some encoded text at the end of the file.<br>
  !<img src="https://i.imgur.com/pnB0T5D.png"><br>
  In the first screenshot, the variable `$L66Rgr` is being assigned to an array containing the php code and the base64 string at the end of the file.<br>
  The array should look similar to this:<br>
  
  `[php_code, base64_text]`<br>
  
  <img src="https://i.imgur.com/u0WLJKE.png"><br>
  A little further along the code is this variable `$L6CRgr`. Here, an array is created as so:<br>
  
  `[/x/i, x, base64_text]`<br>
  
  The first two arguments are just decoded base64 text. The third element is what we want to pay more attention to. It's doing some stuff to the second element of the array created before.<br>
  Following the function call, first run the third element of the array (base64 text at end of file) through a rot13 decoder.<br>
  <img src="https://i.imgur.com/MYvLDUF.png"><br>
  Then take the output and reverse the string.<br>
  <img src="https://i.imgur.com/tJnesuQ.png"><br>
  Then we get, surprise surprise, base64 text. Run that through a base64 decoder.<br>
  <img src="https://i.imgur.com/YxBvzRf.png"><br>
  Now we're getting somewhere...<br>
  <img src="https://i.imgur.com/UFND3UT.png"><br>
  After searching through more php code, the flag is captured!
</details>
