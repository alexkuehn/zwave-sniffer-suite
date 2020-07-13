local p_zwserial = Proto("ZWaveSerial", "ZWave Serial API");

local frametypes = {
    [0x01]="Data",
    [0x06]="ACK",
    [0x15]="NACK",
    [0x18]="CAN"
}

local framedatatypes = {
    [0x00]="Req",
    [0x01]="Res"
}

local serialapicommands = {
    [0x04]="ApplicationCommandHandler"
}

f_dir = ProtoField.uint8("zwserial.direction", "Direction", base.HEX, {[0x00]="ZWave2Host",[0x01]="Host2ZWave"})
f_frametype = ProtoField.uint8("zwserial.frametype", "Frametype", base.HEX, frametypes)
f_length = ProtoField.uint8("zwserial.framelength", "FrameLength", base.DEC)
f_type = ProtoField.uint8("zwserial.datatype", "FrameDataType", base.HEX, framedatatypes)
f_serialcmdid = ProtoField.uint8("zwserial.serialcmdid", "SerialCommandID", base.HEX, serialapicommands)
f_serialcmdparam = ProtoField.bytes("zwserial.serialcmdparam", "SerialCommandParams", base.SPACE)
f_chksum = ProtoField.uint8("zwserial.chksum", "CheckSum", base.HEX)

f_fn_04_rxstat = ProtoField.uint8("zwserial.fn.applicationcommandhandler.rxstat", "RX Stat", base.HEX)
f_fn_04_src = ProtoField.uint8("zwserial.fn.applicationcommandhandler.srcid", "Source ID", base.HEX)
f_fn_04_cmdlen = ProtoField.uint8("zwserial.fn.applicationcommandhandler.cmdlen", "Command Length", base.HEX)
f_fn_04_cmdpayload = ProtoField.bytes("zwserial.fn.cmdpayload", "Command Payload", base.SPACE)
f_fn_04_rssi = ProtoField.uint8("zwserial.fn.applicationcommandhandler.rssi", "Receive RSSI", base.HEX)
f_fn_04_seckey = ProtoField.uint8("zwserial.fn.applicationcommandhandler.seckey", "Security Key", base.HEX)





p_zwserial.fields = {f_dir, f_frametype, f_length, f_type, f_serialcmdid, f_serialcmdparam, f_chksum,
                    f_fn_04_rxstat, f_fn_04_src, f_fn_04_cmdlen, f_fn_04_cmdpayload, f_fn_04_rssi, f_fn_04_seckey
}

function p_zwserial.dissector(buffer,pinfo,tree)
    length = buffer:len()

    if length == 0 then return end
  
    pinfo.cols.protocol = "SerialAPI"

    if buffer(0,1):uint() == 0x01 then
        pinfo.cols.src = "Host"
        pinfo.cols.dst = "ZWave Network"
    else
        pinfo.cols.dst = "Host"
        pinfo.cols.src = "ZWave Network"
    end

    local subtree = tree:add(p_zwserial, buffer(), "ZWaveSerial Protocol Data")
    subtree:add(f_dir,buffer(0,1))
    subtree:add(f_frametype, buffer(1,1))
    pinfo.cols.protocol = frametypes[buffer(1,1):uint()]

    if buffer(1,1):uint() == 0x01 then
        local cmdparams = buffer(5,length-6)
        subtree:add(f_length, buffer(2,1))
        subtree:add(f_type, buffer(3,1))
        subtree:add(f_serialcmdid, buffer(4,1))
        subtree:add(f_chksum,buffer(length-1,1))

        local zw_function = buffer(4,1):uint()
        local functiontree= subtree:add(p_zwserial, buffer(), serialapicommands[zw_function])
        subtree:add(f_serialcmdparam, cmdparams)
        if zw_function == 0x04 then
            decode_ApplicationCommandHandler(cmdparams,pinfo,functiontree)
        end

        pinfo.cols.protocol = framedatatypes[buffer(3,1):uint()]


    end
end

function decode_ApplicationCommandHandler(buffer, pinfo, ftree )
    ftree:add(f_fn_04_rxstat, buffer(0,1))
    ftree:add(f_fn_04_src, buffer(1,1))
    pinfo.cols.src = buffer(1,1):uint()
    ftree:add(f_fn_04_cmdlen, buffer(2,1))
    local cmdlen = buffer(2,1):uint()
    ftree:add(f_fn_04_cmdpayload, buffer(3,cmdlen))
    ftree:add(f_fn_04_rssi, buffer(3+cmdlen,1))
    ftree:add(f_fn_04_seckey, buffer(4+cmdlen,1))
    local cmdpayload = buffer(3,cmdlen)
    
    
end

local wtap_encap_table = DissectorTable.get("wtap_encap")
wtap_encap_table:add(wtap.USER1, p_zwserial)


