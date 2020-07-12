-- zwave-command.lua
-- wireshark dissector plugin for ZWave command classes
-- it expects the PCAP data on USER2 and is used as sub dissector of Zniffer.
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

zwave_protocol = Proto("ZWaveCommand", "ZWave Command Class Protocol")


local cmdclasses = {
  [0x5d]= "Antitheft",
  [0x57]= "ApplicationCapability",
  [0x22]= "ApplicationStatus",
  [0x85]= "Association",
  [0x9b]= "AssociationCommandConfiguration",
  [0x59]= "AssociationGrpInfo",
  [0x95]= "AvContentDirectoryMd",
  [0x97]= "AvContentSearchMd",
  [0x96]= "AvRendererStatus",
  [0x99]= "AvTaggingMd",
  [0x66]= "BarrierOperator",
  [0x20]= "Basic",
  [0x36]= "BasicTariffInfo",
  [0x50]= "BasicWindowCovering",
  [0x80]= "Battery",
  [0x5b]= "CentralScene",
  [0x2a]= "ChimneyFan",
  [0x46]= "ClimateControlSchedule",
  [0x81]= "Clock",
  [0x70]= "Configuration",
  [0x21]= "ControllerReplication",
  [0x56]= "Crc16Encap",
  [0x3a]= "DcpConfig",
  [0x3b]= "DcpMonitor",
  [0x5a]= "DeviceResetLocally",
  [0x65]= "Dmx",
  [0x62]= "DoorLock",
  [0x4c]= "DoorLockLogging",
  [0x90]= "EnergyProduction",
  [0x6f]= "EntryControl",
  [0x7a]= "FirmwareUpdateMd",
  [0x8c]= "GeographicLocation",
  [0x7b]= "GroupingName",
  [0x82]= "Hail",
  [0x39]= "HrvControl",
  [0x37]= "HrvStatus",
  [0x6d]= "HumidityControlMode",
  [0x6e]= "HumidityControlOperatingState",
  [0x64]= "HumidityControlSetpoint",
  [0x74]= "InclusionController",
  [0x87]= "Indicator",
  [0x5c]= "IpAssociation",
  [0x9a]= "IpConfiguration",
  [0x6b]= "Irrigation",
  [0x89]= "Language",
  [0x76]= "Lock",
  [0x69]= "Mailbox",
  [0x91]= "ManufacturerProprietary",
  [0x72]= "ManufacturerSpecific",
  [0xef]= "Mark",
  [0x32]= "Meter",
  [0x35]= "MeterPulse",
  [0x3c]= "MeterTblConfig",
  [0x3d]= "MeterTblMonitor",
  [0x3e]= "MeterTblPush",
  [0x51]= "MtpWindowCovering",
  [0x60]= "MultiChannel",
  [0x8e]= "MultiChannelAssociation",
  [0x8f]= "MultiCmd",
  [0x4d]= "NetworkManagementBasic",
  [0x34]= "NetworkManagementInclusion",
  [0x67]= "NetworkManagementInstallationMaintenance",
  [0x54]= "NetworkManagementPrimary",
  [0x52]= "NetworkManagementProxy",
  [0x77]= "NodeNaming",
  [0xf0]= "NonInteroperable",
  [0x00]= "NoOperation",
  [0x71]= "Notification",
  [0x73]= "Powerlevel",
  [0x3f]= "Prepayment",
  [0x41]= "PrepaymentEncapsulation",
  [0x88]= "Proprietary",
  [0x75]= "Protection",
  [0x48]= "RateTblConfig",
  [0x49]= "RateTblMonitor",
  [0x7d]= "RemoteAssociation",
  [0x7c]= "RemoteAssociationActivate",
  [0x2b]= "SceneActivation",
  [0x2c]= "SceneActuatorConf",
  [0x2d]= "SceneControllerConf",
  [0x53]= "Schedule",
  [0x4e]= "ScheduleEntryLock",
  [0x93]= "ScreenAttributes",
  [0x92]= "ScreenMd",
  [0x98]= "Security",
  [0x9f]= "Security2",
  [0x24]= "SecurityPanelMode",
  [0x2e]= "SecurityPanelZone",
  [0x2f]= "SecurityPanelZoneSensor",
  [0x9c]= "SensorAlarm",
  [0x30]= "SensorBinary",
  [0x9e]= "SensorConfiguration",
  [0x31]= "SensorMultilevel",
  [0x9d]= "SilenceAlarm",
  [0x94]= "SimpleAvControl",
  [0x6c]= "Supervision",
  [0x27]= "SwitchAll",
  [0x25]= "SwitchBinary",
  [0x33]= "SwitchColor",
  [0x26]= "SwitchMultilevel",
  [0x28]= "SwitchToggleBinary",
  [0x29]= "SwitchToggleMultilevel",
  [0x4a]= "TariffConfig",
  [0x4b]= "TariffTblMonitor",
  [0x44]= "ThermostatFanMode",
  [0x45]= "ThermostatFanState",
  [0x38]= "ThermostatHeating",
  [0x40]= "ThermostatMode",
  [0x42]= "ThermostatOperatingState",
  [0x47]= "ThermostatSetback",
  [0x43]= "ThermostatSetpoint",
  [0x8a]= "Time",
  [0x8b]= "TimeParameters",
  [0x55]= "TransportService",
  [0x63]= "UserCode",
  [0x86]= "Version",
  [0x84]= "WakeUp",
  [0x6a]= "WindowCovering",
  [0x02]= "ZensorNet",
  [0x23]= "Zip",
  [0x4f]= "Zip6lowpan",
  [0x5f]= "ZipGateway",
  [0x68]= "ZipNaming",
  [0x58]= "ZipNd",
  [0x61]= "ZipPortal",
  [0x5e]= "ZwaveplusInfo"
}

zw_cmdclass = ProtoField.uint8("zwave.cmd.class", "CommandClass", base.HEX, cmdclasses)    
zw_cmd  = ProtoField.uint8("zwave.cmd.cmd", "Command", base.HEX )    
zw_cmdparam = ProtoField.bytes("zwave.cmd.params", "Command Parameters", base.SPACE )    
zwave_protocol.fields = {zw_cmdclass, zw_cmd, zw_cmdparam}
function zwave_protocol.dissector(buffer, pinfo, tree)
  length = buffer:len()
  if length == 0 then return end
  
  local cmdprototree = tree:add(zwave_protocol, buffer(), "Command Class Protocol Data")
  cmdprototree:add(zw_cmdclass, buffer(0,1))  
  cmdprototree:add(zw_cmd, buffer(1,1))  
  cmdprototree:add(zw_cmdparam, buffer(2,buffer:len()-2))  
  pinfo.cols.info = cmdclasses[buffer(0,1):uint()]

end

local wtap_encap_table = DissectorTable.get("wtap_encap")
wtap_encap_table:add(wtap.USER2, zwave_protocol)