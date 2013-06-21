-- Lua Dissector for SMPTE 2022-6  
-- Author: Thomas Edwards (thomas.edwards@fox.com)
--
-- to use in Wireshark:
-- 1) Ensure your Wireshark works with Lua plugins - "About Wireshark" should say it is compiled with Lua
-- 2) Install this dissector in the proper plugin directory - see "About Wireshark/Folders" to see Personal
--    and Global plugin directories.  After putting this dissector in the proper folder, "About Wireshark/Plugins"
--    should list "SMPTE-2022-6.lua" 
-- 3) In Wireshark Preferences, under "Protocols", set SMPTE_2022_6 as dynamic payload type 98
-- 4) Capture packets of SMPTE 2022-6
-- 5) "Decode As" those UDP packets as RTP
-- 6) You will now see the SMPTE 2022-6 Data dissection of the RTP payload
--
-- This program is free software; you can redistribute it and/or
-- modify it under the terms of the GNU General Public License
-- as published by the Free Software Foundation; either version 2
-- of the License, or (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
------------------------------------------------------------------------------------------------  
do  
    local smpte_2022_6 = Proto("smpte_2022_6", "SMPTE 2022-6")  
     
    local prefs = smpte_2022_6.prefs  
    prefs.dyn_pt = Pref.uint("SMPTE 2022-6 dynamic payload type", 0, "The value > 95")  
 
    local F = smpte_2022_6.fields

    F.Ext = ProtoField.uint8("smpte_2022_6.Ext","Extension field (Ext)",base.HEX,nil,0xF0)
    F.F = ProtoField.bool("smpte_2022_6.F","Video source format flag (F)",8,{"Present","Not Present"},0x08)
    F.VSID = ProtoField.uint8("smpte_2022_6.VSID","Video source ID (VSID)",base.HEX,{[0]="primary stream",[1]="protect stream",[2]="reserved",[3]="reserved",[4]="reserved",[5]="reserved",[6]="reserved",[7]="reserved"},0x07) 
    F.FRCount = ProtoField.uint8("smpte_2022_6.FRCount","Frame Count (FRCount)")
    F.R = ProtoField.uint8("smpte_2022_6.R","Reference for time stamp (R)",base.HEX,{[0]="not locked",[1]="reserved",[2]="locked to UTC time/frequency reference",[3]="localed to a private time/frequency reference"},0xC0)
    F.S = ProtoField.uint8("smpte_2022_6.S","Video Payload Scrambing (S)",base.HEX,{[0]="not scrambled",[1]="reserved",[2]="reserved",[3]="reserved"},0x30)
    F.FEC = ProtoField.uint8("smpte_2022_6.FEC","FEC usage (FEC)",base.HEX,{[0]="No FEC stream",[1]="L(Column) FEC utilized",[2]="L&D (Column & Row) FEC utilized",[3]="reserved",[4]="reserved",[5]="reserved",[6]="reserved",[7]="reserved"},0x0E)
    F.CF = ProtoField.uint16("smpte_2022_6.CF","Clock Frequency (CF)",base.HEX,{[0]="No time stamp",[1]="27 MHz",[2]="148.5 MHz",[3]="148.5/1.001 MHz",[4]="297 MHz",[5]="297/1.001 MHz"},0x01E0) 
    F.MAP = ProtoField.uint8("smpte_2022_6.MAP","Video source format (MAP)",base.HEX,{[0]="Direct sample structure",[1]="SMPTE ST 425-1 Level B-DL Mapping of 372 Dual-Link",[2]="SMPTE ST 425-1 Level B-DS Mapping of two ST 292-1 Streams"},0xF0)
    F.FRAME = ProtoField.uint16("smpte_2022_6.FRAME","Frame structure (FRAME)",base.HEX,{[0x10]="720x486 active, interlaced",[0x11]="720x576 active, interlaced",[0x20]="1920x1080 active, interlaced",[0x21]="1920x1080 active, progressive",[0x22]="1920x1080 active, PsF",[0x23]="2048x1080 active, progressive",[0x24]="2048x1080, PsF",[0x30]="1280x720 active, progressive"},0x0FF0)

    frame_rates={
    [0x00]="Unknown/Unspecified frame rate 2.970 GHz signal",[0x01]="Unknown/Unspecified frame rate 2.970/1.001 GHz signal",
    [0x02]="Unknown/Unspecified frame rate 1.485 GHz signal",[0x03]="Unknown/Unspecified frame rate 1.485/1.001 GHz signal",
    [0x04]="Unknown/Unspecified frame rate 0.270 GHz signal",
    [0x10]="60",[0x11]="60/1.001",[0x12]="50",[0x13]="reserved",[0x14]="48",[0x15]="48/1.001",[0x16]="30",[0x17]="30/1.001",
    [0x18]="25",[0x19]="reserved",[0x1A]="24",[0x1B]="24/1.001"}
    
    F.FRATE = ProtoField.uint16("smpte_2022_6.FRATE","Frame rate (FRATE)",base.HEX,frame_rates,0x0FF0)

    sampling={
    [0x00]="Unknown/Unspecified",[0x01]="4:2:2 10 bits",[0x02]="4:4:4 10 bits",[0x03]="4:4:4:4 10 bits",[0x04]="Reserved",[0x05]="4:2:2 12 bits",
    [0x06]="4:4:4 12 bits",[0x07]="4:4:4:4 12 bits",[0x08]="4:2:2:4 12 bits"
    }

    F.SAMPLE= ProtoField.uint8("smpte_2022_6.SAMPLE","Picture samping (SAMPLE)",base.HEX,sampling,0x0F)
    F.video_ts=ProtoField.uint32("smpte_2022_6.video_ts","Video timestamp (video_ts)")
    F.header_ext_tag=ProtoField.uint8("smpte_2022_6.header_ext_tag","Header extension tag (header_ext_tag)",base.HEX)
    F.header_ext_len=ProtoField.uint8("smpte_2022_6.header_ext_len","Header extension length (header_ext_len)")
    F.header_ext_val=ProtoField.bytes("smpte_2022_6.header_ext_val","Header extension value")
    F.HBRM_payload=ProtoField.bytes("smpte_2022_6.HBRM_payload","HBRM_payload")
 
    function smpte_2022_6.dissector(tvb, pinfo, tree)  
        local subtree = tree:add(smpte_2022_6, tvb(),"SMPTE 2022-6 Data")  
	subtree:add(F.Ext, tvb(0,1))
	local EXT=tvb(0,1):bitfield(0,4)
	subtree:add(F.F, tvb(0,1))
	subtree:add(F.VSID, tvb(0,1))
	subtree:add(F.FRCount,tvb(1,1))
	subtree:add(F.R,tvb(2,1))
	subtree:add(F.S,tvb(2,1))
	subtree:add(F.FEC,tvb(2,1))
	subtree:add(F.CF,tvb(2,2))
	local CF=tvb(2,2):bitfield(7,4)
	subtree:add(F.MAP,tvb(4,1))
	subtree:add(F.FRAME,tvb(4,2))
	subtree:add(F.FRATE,tvb(5,2))
	subtree:add(F.SAMPLE,tvb(6,1))
	local offset=8
	if CF>0 then
		subtree:add(F.video_ts,tvb(8,4))
		offset=offset+4
	end
	local ext_start = offset
	local ext_bytes_left = EXT*4
	if EXT>0 then
		while ext_bytes_left>0 do
			local ext_tag = tvb(offset,1):uint()
			if ext_tag>0 then
				subtree:add(F.header_ext_tag,tvb(offset,1))
				subtree:add(F.header_ext_len,tvb(offset+1,1))
				local ext_len=tvb(offset+1,1):uint()
				subtree:add(F.header_ext_val,tvb(offset+2,ext_len))
				offset=offset+2+ext_len
				ext_bytes_left=ext_bytes_left-2-ext_len
			else
				-- PAD tag detected, skip over all remaining extension bytes
				ext_bytes_left=0
			end
		end
		-- ensure word alignment at end of header extension
		offset=ext_start+EXT*4	
	end		
	subtree:add(F.HBRM_payload,tvb(offset,1376))
    end  
  
    -- register dissector to dynamic payload type dissectorTable  
    local dyn_payload_type_table = DissectorTable.get("rtp_dyn_payload_type")  
    dyn_payload_type_table:add("SMPTE_2022_6", smpte_2022_6)  
  
    -- register dissector to RTP payload type
    local payload_type_table = DissectorTable.get("rtp.pt")  
    local old_dissector = nil  
    local old_dyn_pt = 0  
    function smpte_2022_6.init()  
        if (prefs.dyn_pt ~= old_dyn_pt) then
            if (old_dyn_pt > 0) then
                if (old_dissector == nil) then
                    payload_type_table:remove(old_dyn_pt, smpte_2022_6)  
                else
                    payload_type_table:add(old_dyn_pt, old_dissector)  
                end  
            end  
            old_dyn_pt = prefs.dyn_pt
            old_dissector = payload_type_table:get_dissector(old_dyn_pt)  
            if (prefs.dyn_pt > 0) then  
                payload_type_table:add(prefs.dyn_pt, smpte_2022_6)  
            end  
        end   
    end  
end
