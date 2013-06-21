smtpe2022-6-dissector
=====================

Wireshark dissector in Lua for SMPTE 2022-6 data in RTP

to use in Wireshark:

1) Ensure your Wireshark works with Lua plugins - "About Wireshark" should say it is compiled with Lua

2) Install this dissector in the proper plugin directory - see "About Wireshark/Folders" to see Personal
   and Global plugin directories.  After putting this dissector in the proper folder, "About Wireshark/Plugins"
   should list "SMPTE-2022-6.lua" 

3) In Wireshark Preferences, under "Protocols", set SMPTE_2022_6 as dynamic payload type 98

4) Capture packets of SMPTE 2022-6

5) "Decode As" those UDP packets as RTP

6) You will now see the SMPTE 2022-6 Data dissection of the RTP payload
