-- zniffer-dissector.lua
-- wireshark dissector plugin for Zniffer Zwave packet decoding
-- it expects the PCAP data on USER0
--
-- Copyright C) 2020 Alexander Kühn <prj@alexkuehn.de>
-- 
-- This program is free software: you can redistribute it and/or modify it under
-- the terms of the GNU Lesser General Public License as published by the Free
-- Software Foundation, either version 3 of the License, or (at your option) any
-- later version.
-- 
-- This program is distributed in the hope that it will be useful, but WITHOUT
-- ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
-- FOR A PARTICULAR PURPOSE. See the GNU General Lesser Public License for more
-- details.
-- 
-- You should have received a copy of the GNU Lesser General Public License along
-- with this program.  If not, see <http://www.gnu.org/licenses/>.

zniffer_protocol = Proto("Zniffer", "ZWave Zniffer Serial Protocol")


local framespeeds = {
  [0x2100] = "40kbit/s, Ch1",
  [0x0200] = "100kbit/s, Ch0",
  [0x2000] = "9.6kbit/s, Ch1"
}

local zniffer_frametypes = {
  [0x01] = "ZWave Packet",
  [0x04] = "WakeStart",
  [0x05] = "WakeStop",
  [0xFF] = "Unidentified Packet"
}

local zniffer_boolprot = {
  [0] = "False",
  [1] = "True"
}
local mpdu_headertype = {
  [0x01] = "Singlecast",
  [0x02] = "Multicast",
  [0x03] = "Ack",
  [0x04] = "NotUsed",
  [0x05] = "NotUsed",
  [0x06] = "NotUsed",
  [0x07] = "NotUsed",
  [0x08] = "Routed",
  [0x09] = "NotUsed",
  [0x0A] = "NotUsed",
  [0x0B] = "NotUsed",
  [0x0C] = "Reserved",
  [0x0D] = "Reserved",
  [0x0E] = "Reserved",
  [0x0F] = "Reserved"
}

local mpdu_beamtype = {
  [0x00] = "No Beam",
  [0x01] = "Short continous beam",
  [0x02] = "Long continous beam",
  [0x03] = "Reserved",
}
zn_frametype = ProtoField.uint8("zniffer.frametype", "frameType", base.HEX, zniffer_frametypes)
zn_framefill1 = ProtoField.bytes("zniffer.framefill1", "framefill1", base.SPACE)
zn_framespeed = ProtoField.uint16("zniffer.framespeed", "frameSpeed", base.HEX, framespeeds)
zn_framefill2 = ProtoField.bytes("zniffer.framefill2", "framefill2", base.SPACE)
zn_rssi = ProtoField.uint8("zniffer.rssi", "RSSI", base.HEX)
zn_length = ProtoField.uint8("zniffer.framelength", "framelength", base.DEC)
zn_mpdu = ProtoField.bytes("zniffer.mpdu.payload", "MPDU payload", base.SPACE)


zn_frame_crc = ProtoField.uint8("zniffer.mpdu.crc", "CRC", base.HEX)
zn_frame_homeid = ProtoField.bytes("zniffer.mpdu.homeid", "HomeID", base.SPACE)
zn_frame_srcid = ProtoField.uint8("zniffer.mpdu.srcid", "SourceID", base.HEX)
zn_frame_ctrl = ProtoField.bytes("zniffer.mpdu.framectrl", "FrameControl", base.SPACE)
zn_frame_len = ProtoField.uint8("zniffer.mpdu.framelen", "MPDU Length", base.DEC)
zn_frame_ctrl_routed = ProtoField.uint16("zniffer.mpdu.framectrl.routed", "Routed", base.DEC,zniffer_boolprot ,0x8000)
zn_frame_ctrl_ackreq = ProtoField.uint16("zniffer.mpdu.framectrl.ackreq", "Ack Req", base.DEC,zniffer_boolprot ,0x4000)
zn_frame_ctrl_lowspeed = ProtoField.uint16("zniffer.mpdu.framectrl.lowspeed", "LowSpeed", base.DEC,zniffer_boolprot ,0x2000)
zn_frame_ctrl_speedmod = ProtoField.uint16("zniffer.mpdu.framectrl.speedmod", "SpeedModified", base.DEC,zniffer_boolprot ,0x1000)
zn_frame_ctrl_headertype = ProtoField.uint16("zniffer.mpdu.framectrl.headertype", "HeaderType", base.DEC,mpdu_headertype ,0x0F00)
zn_frame_ctrl_res1 = ProtoField.uint16("zniffer.mpdu.framectrl.res1", "Reserved1", base.DEC,zniffer_boolprot ,0x0080)
zn_frame_ctrl_beaminfo = ProtoField.uint16("zniffer.mpdu.framectrl.beaminfo", "BeamInfo", base.DEC,mpdu_beamtype ,0x0060)
zn_frame_ctrl_res2 = ProtoField.uint16("zniffer.mpdu.framectrl.res2", "Reserved2", base.DEC,zniffer_boolprot ,0x0010)
zn_frame_ctrl_seqnr = ProtoField.uint16("zniffer.mpdu.framectrl.seqnr", "Sequence Number", base.HEX,nil ,0x000F)
zn_frame_dstid = ProtoField.bytes("zniffer.mpdu.framectrl.dstid", "DestinationID", base.SPACE)

zn_frame_route_failedhop = ProtoField.uint8("zniffer.mpdu.route.failedhop", "MPDU Route Failed Hop", base.DEC, nil, 0xF0)
zn_frame_route_flag_dir = ProtoField.uint8("zniffer.mpdu.route.flag.dir", "MPDU Route Direction", base.HEX, zniffer_boolprot, 0x01)
zn_frame_route_flag_ack = ProtoField.uint8("zniffer.mpdu.route.flag.ack", "MPDU Route Ack", base.HEX, zniffer_boolprot, 0x02)
zn_frame_route_flag_err = ProtoField.uint8("zniffer.mpdu.route.flag.err", "MPDU Route Error", base.HEX, zniffer_boolprot, 0x04)
zn_frame_route_flag_extheader = ProtoField.uint8("zniffer.mpdu.route.flag.extheader", "MPDU Route Extended Header", base.HEX, zniffer_boolprot, 0x08)

zn_frame_route_len = ProtoField.uint8("zniffer.mpdu.route.len", "MPDU Route Length", base.HEX, nil, 0xF0)
zn_frame_route_hop = ProtoField.uint8("zniffer.mpdu.route.hop", "MPDU Route Hop", base.HEX, nil, 0x0F)
zn_frame_route_path = ProtoField.bytes("zniffer.mpdu.route.path", "MPDU Route Path", base.SPACE)

zn_frame_extheader_len = ProtoField.uint8("zniffer.mpdu.extheader.len", "MPDU Extended Header Length", base.HEX, nil, 0xF0)
zn_frame_extheader_flags = ProtoField.uint8("zniffer.mpdu.extheader.flags", "MPDU Extended Header Flags", base.HEX, nil, 0x0F)
zn_frame_extheader_data = ProtoField.bytes("zniffer.mpdu.extheader.data", "MPDU Extended Header Data", base.SPACE)

zniffer_protocol.fields = {zn_frametype, zn_framefill1, zn_framespeed, zn_rssi, zn_framefill2, zn_length, zn_mpdu,
    zn_frame_crc, zn_frame_homeid, zn_frame_srcid, zn_frame_ctrl, zn_frame_len,
  zn_frame_ctrl_routed, zn_frame_ctrl_ackreq, zn_frame_ctrl_lowspeed, zn_frame_ctrl_speedmod, zn_frame_ctrl_headertype,
  zn_frame_ctrl_res1, zn_frame_ctrl_beaminfo, zn_frame_ctrl_res2, zn_frame_ctrl_seqnr, zn_frame_dstid,
  zn_frame_route_failedhop, 
  zn_frame_route_flag_dir, zn_frame_route_flag_ack, zn_frame_route_flag_err, zn_frame_route_flag_extheader,
  zn_frame_route_len, zn_frame_route_hop, zn_frame_route_path,
  zn_frame_extheader_len, zn_frame_extheader_flags, zn_frame_extheader_data }



function calc_fcs(buf)
  local checksum = 0xFF
  for index=0,buf:len()-1 do
    local b = buf(index,1):uint()
    checksum = bit.bxor(checksum, b)
  end
  return checksum
end

function zniffer_protocol.dissector(buffer, pinfo, tree)
  length = buffer:len()
  if length == 0 then return end
  
  local subtree = tree:add(zniffer_protocol, buffer(), "Zniffer Protocol Data")

  local frametype = buffer(0,1):uint()
  local frametype_name = zniffer_frametypes[frametype]


  subtree:add(zn_frametype, buffer(0,1) ):append_text( " (" .. frametype_name .. ")")
  pinfo.cols.protocol = frametype_name
  
  local mpdutree = nil
  
  local rssi = 0
  local mpdustart = 0
  
  if frametype == 0x01 then 
    subtree:add(zn_framefill1, buffer(1,2))
    subtree:add(zn_framespeed, buffer(3,2))
    subtree:add(zn_rssi, buffer(5,1))
    subtree:add(zn_framefill2, buffer(6,2))
    subtree:add(zn_length, buffer(8,1))
    mpdustart = 9  
    rssi =  buffer(5,1):uint()
  elseif frametype == 0x04 then 
    rssi =  buffer(5,1):uint()  
  elseif frametype == 0x05 then 
    rssi =  buffer(3,1):uint()
  elseif frametype == 0xFF then

  end
  mpdutree = subtree:add(zniffer_protocol, buffer(), frametype_name .. " Protocol Data")

  if frametype == 0x01 then
    local fcs = calc_fcs(buffer(mpdustart,buffer:len()-mpdustart-1))
    local crcrange = buffer(buffer:len()-1,1)


    if fcs ~= crcrange:uint() then
      pinfo.cols.protocol = "CRC Error"
    else
      local homeid = buffer(mpdustart,4)
      pinfo.cols.net_src = homeid:bytes():tohex(false, ' ')
      local srcid = buffer(mpdustart+4,1)
      local framectrl = buffer(mpdustart+5,2)
      local framectrlheadertype = bit.rshift(framectrl:uint(), 8)
      local framectrlrouted = bit.band(framectrl:uint(), 0x8000)
      framectrlheadertype = bit.band(framectrlheadertype, 0x0F)

      mpdutree:add(zn_frame_homeid, homeid)
      mpdutree:add(zn_frame_srcid,srcid)
      mpdutree:add(zn_frame_ctrl,framectrl)
      local framectrlsubtree = mpdutree:add(mpdutree, buffer(), "Frame Control Field")
      framectrlsubtree:add(zn_frame_ctrl_routed, framectrl)
      framectrlsubtree:add(zn_frame_ctrl_ackreq, framectrl)
      framectrlsubtree:add(zn_frame_ctrl_lowspeed, framectrl)
      framectrlsubtree:add(zn_frame_ctrl_speedmod, framectrl)
      framectrlsubtree:add(zn_frame_ctrl_headertype, framectrl)
      framectrlsubtree:add(zn_frame_ctrl_res1, framectrl)
      framectrlsubtree:add(zn_frame_ctrl_beaminfo, framectrl)
      framectrlsubtree:add(zn_frame_ctrl_res2, framectrl)
      framectrlsubtree:add(zn_frame_ctrl_seqnr, framectrl)
      
      mpdutree:add(zn_frame_len, buffer(mpdustart+7,1))

      local dstlen = 0
      
      if framectrlheadertype == 0x02 then
        dstlen = 29
      else 
        dstlen = 1        
        pinfo.cols.dst=buffer(mpdustart+8, dstlen):uint()
      end

      pinfo.cols.protocol = mpdu_headertype[framectrlheadertype]

      local dstid = buffer(mpdustart+8, dstlen)
      


      mpdutree:add(zn_frame_dstid, dstid)
      pinfo.cols.src=srcid:uint()
      mpdutree:add(zn_frame_crc, crcrange)

      local zw_msdu_offset = mpdustart+8+dstlen
      
      -- determine if MDSU contains additional routing information
      if framectrlheadertype == 0x08 or framectrlrouted > 0 then
        if framectrlheadertype ~= 0x08 then
          pinfo.cols.protocol:append("| Routed")
        end
        mpdutree:add(zn_frame_route_failedhop, buffer(zw_msdu_offset,1))
        mpdutree:add(zn_frame_route_flag_dir, buffer(zw_msdu_offset,1))
        mpdutree:add(zn_frame_route_flag_ack, buffer(zw_msdu_offset,1))
        mpdutree:add(zn_frame_route_flag_err, buffer(zw_msdu_offset,1))
        mpdutree:add(zn_frame_route_flag_extheader, buffer(zw_msdu_offset,1))
        mpdutree:add(zn_frame_route_len, buffer(zw_msdu_offset+1,1))
        mpdutree:add(zn_frame_route_hop, buffer(zw_msdu_offset+1,1))
        
        local route_len = bit.rshift(buffer(zw_msdu_offset+1,1):uint(), 4)
        mpdutree:add(zn_frame_route_path, buffer(zw_msdu_offset+2,route_len))
        local extheader = bit.band(buffer(zw_msdu_offset,1):uint(), 0x08)
        local routeerr = bit.band(buffer(zw_msdu_offset,1):uint(), 0x04)
        local routeack = bit.band(buffer(zw_msdu_offset,1):uint(), 0x02)
        if routeack ~= 0 then
          pinfo.cols.info = "Routed ACK"
        end
        if routeerr ~= 0 then
          pinfo.cols.info = "Routing Error"
        end

        -- we have additional data with routing information
        zw_msdu_offset  = zw_msdu_offset + 2 + route_len
    
        -- there is something like an extended header
        -- see if its there and add dissection of it
        if extheader ~= 0 then
          local extheader_len =  bit.rshift(buffer(zw_msdu_offset,1):uint(), 4)
          mpdutree:add(zn_frame_extheader_len,  buffer(zw_msdu_offset,1))
          mpdutree:add(zn_frame_extheader_flags,  buffer(zw_msdu_offset,1))
          mpdutree:add(zn_frame_extheader_data,  buffer(zw_msdu_offset+1,extheader_len))
          -- we have additional data with extended header info
          zw_msdu_offset  = zw_msdu_offset + 1 + extheader_len
    
        end



      end

      local zw_msdu_len = buffer:len()-zw_msdu_offset-1

      
      payloaddissector=DissectorTable.get("wtap_encap"):get_dissector(47)
      payloaddissector:call(buffer(zw_msdu_offset,zw_msdu_len):tvb(), pinfo, tree)
    
    end

    
  else
    mpdutree:add(zn_mpdu, buffer(mpdustart,buffer:len()-mpdustart))
  end
  
  pinfo.cols.rssi = rssi
   
end

local wtap_encap_table = DissectorTable.get("wtap_encap")
wtap_encap_table:add(wtap.USER0, zniffer_protocol)