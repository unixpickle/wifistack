package frames

import "strconv"

// A ElementID is an element ID for fields in 802.11 management frames.
// These IDs are defined in section 8.4.2.1 of the IEEE 802.11-2012 standard.
type ElementID int

const (
	ElementIDSSID                              ElementID = 0
	ElementIDSupportedRates                              = 1
	ElementIDFHParameterSet                              = 2
	ElementIDDSSSParameterSet                            = 3
	ElementIDCFParameterSet                              = 4
	ElementIDTIM                                         = 5
	ElementIDIBSSParameterSet                            = 6
	ElementIDCountry                                     = 7
	ElementIDHoppingPatternParams                        = 8
	ElementIDHoppingPatternTable                         = 9
	ElementIDRequest                                     = 10
	ElementIDBSSLoad                                     = 11
	ElementIDEDCAParameterSet                            = 12
	ElementIDTSPEC                                       = 13
	ElementIDTCLAS                                       = 14
	ElementIDSchedule                                    = 15
	ElementIDChallengeText                               = 16
	ElementIDPowerConstraint                             = 32
	ElementIDPowerCapability                             = 33
	ElementIDTPCRequest                                  = 34
	ElementIDTPCReport                                   = 35
	ElementIDSupportedChannels                           = 36
	ElementIDChannelSwitchAnnouncement                   = 37
	ElementIDMeasurementRequest                          = 38
	ElementIDMeasurementReport                           = 39
	ElementIDQuiet                                       = 40
	ElementIDIBSSDFS                                     = 41
	ElementIDERP                                         = 42
	ElementIDTSDelay                                     = 43
	ElementIDTCLASProcessing                             = 44
	ElementIDHTCapabilities                              = 45
	ElementIDQoSCapability                               = 46
	ElementIDRSN                                         = 48
	ElementIDExtendedSupportedRates                      = 50
	ElementIDAPChannelReport                             = 51
	ElementIDNeighborReport                              = 52
	ElementIDRCPI                                        = 53
	ElementIDMDE                                         = 54
	ElementIDFTE                                         = 55
	ElementIDTimeoutInterval                             = 56
	ElementIDRICData                                     = 57
	ElementIDDSERegisteredLocation                       = 58
	ElementIDSupportedOperatingClasses                   = 59
	ElementIDExtendedChannelSwitchAnnouncement           = 60
	ElementIDHTOperation                                 = 61
	ElementIDSecondaryChannelOffset                      = 62
	ElementIDBSSAverageAccessDelay                       = 63
	ElementIDAntenna                                     = 64
	ElementIDRSNI                                        = 65
	ElementIDMeasurementPilotTransmission                = 66
	ElementIDBSSAvailableAdmissionCapacity               = 67
	ElementIDBSSACAccessDelay                            = 68
	ElementIDTimeAdvertisement                           = 69
	ElementIDRMEnabledCapabilities                       = 70
	ElementIDMultipleBSSID                               = 71
	ElementIDOverlappingBSSScanParameters                = 74
	ElementIDRICDescriptor                               = 75
	ElementIDManagementMIC                               = 76
	ElementIDEventRequest                                = 78
	ElementIDEventReport                                 = 79
	ElementIDDiagnosticRequest                           = 80
	ElementIDDiagnosticReport                            = 81
	ElementIDLocationParameters                          = 82
	ElementIDNontransmittedBSSIDCapability               = 83
	ElementIDSSIDList                                    = 84
	ElementIDFMSDescriptor                               = 86
	ElementIDFMSRequest                                  = 87
	ElementIDFMSResponse                                 = 88
	ElementIDQoSTrafficCapability                        = 89
	ElementIDBSSMaxIdlePeriod                            = 90
	ElementIDTFSRequest                                  = 91
	ElementIDTFSResponse                                 = 92
	ElementIDTIMBroadcastRequest                         = 94
	ElementIDTIMBroadcastResponse                        = 95
	ElementIDCollocatedInterferenceReport                = 96
	ElementIDChannelUsage                                = 97
	ElementIDTimeZone                                    = 98
	ElementIDDMSRequest                                  = 99
	ElementIDDMSResponse                                 = 100
	ElementIDLinkIdentifier                              = 101
	ElementIDWakeupSchedule                              = 102
	ElementIDChannelSwitchTiming                         = 104
	ElementIDPTIControl                                  = 105
	ElementIDTPUBufferStatus                             = 106
	ElementIDInterworking                                = 107
	ElementIDAdvertisementProtocol                       = 108
	ElementIDExpeditedBandwidthRequest                   = 109
	ElementIDQoSMapSet                                   = 110
	ElementIDRoamingConsortium                           = 111
	ElementIDEmergencyAlertIdentifier                    = 112
	ElementIDMeshConfiguration                           = 113
	ElementIDMeshID                                      = 114
	ElementIDMeshLinkMetricReport                        = 115
	ElementIDCongestionNotification                      = 116
	ElementIDMeshPeeringManagement                       = 117
	ElementIDMeshChannelSwitchParameters                 = 118
	ElementIDMeshAwakeWindow                             = 119
	ElementIDBeaconTiming                                = 120
	ElementIDMCCAOPSetupRequest                          = 121
	ElementIDMCCAOPSetupReply                            = 122
	ElementIDMCCAOPAdvertisement                         = 123
	ElementIDMCCAOPTeardown                              = 124
	ElementIDGANN                                        = 125
	ElementIDRANN                                        = 126
	ElementIDExtendedCapabilities                        = 127
	ElementIDPREQ                                        = 130
	ElementIDPREP                                        = 131
	ElementIDPERR                                        = 132
	ElementIDPXU                                         = 137
	ElementIDPXUC                                        = 138
	ElementIDAuthenticatedMeshPeeringExchange            = 139
	ElementIDMIC                                         = 140
	ElementIDDestinationURI                              = 141
	ElementIDUAPSDCoexistence                            = 142
	ElementIDMCCAOPAdvertisementOverview                 = 174
	ElementIDVendorSpecific                              = 221
)

var elementIDNames = map[ElementID]string{
	ElementIDSSID:                              "SSID",
	ElementIDSupportedRates:                    "Supported rates",
	ElementIDFHParameterSet:                    "FH Parameter Set",
	ElementIDDSSSParameterSet:                  "DSSS Parameter Set",
	ElementIDCFParameterSet:                    "CF Parameter Set",
	ElementIDTIM:                               "TIM",
	ElementIDIBSSParameterSet:                  "IBSS Parameter Set",
	ElementIDCountry:                           "Country",
	ElementIDHoppingPatternParams:              "Hopping Pattern Parameters",
	ElementIDHoppingPatternTable:               "Hopping Pattern Table",
	ElementIDRequest:                           "Request",
	ElementIDBSSLoad:                           "BSS Load",
	ElementIDEDCAParameterSet:                  "EDCA Parameter Set",
	ElementIDTSPEC:                             "TSPEC",
	ElementIDTCLAS:                             "TCLAS",
	ElementIDSchedule:                          "Schedule",
	ElementIDChallengeText:                     "Challenge text",
	ElementIDPowerConstraint:                   "Power Constraint",
	ElementIDPowerCapability:                   "Power Capability",
	ElementIDTPCRequest:                        "TPC Request",
	ElementIDTPCReport:                         "TPC Report",
	ElementIDSupportedChannels:                 "Supported Channels",
	ElementIDChannelSwitchAnnouncement:         "Channel Switch Announcement",
	ElementIDMeasurementRequest:                "Measurement Request",
	ElementIDMeasurementReport:                 "Measurement Report",
	ElementIDQuiet:                             "Quiet",
	ElementIDIBSSDFS:                           "IBSS DFS",
	ElementIDERP:                               "ERP",
	ElementIDTSDelay:                           "TS Delay",
	ElementIDTCLASProcessing:                   "TCLAS Processing",
	ElementIDHTCapabilities:                    "HT Capabilities",
	ElementIDQoSCapability:                     "QoS Capability",
	ElementIDRSN:                               "RSN",
	ElementIDExtendedSupportedRates:            "Extended Supported Rates",
	ElementIDAPChannelReport:                   "AP Channel Report",
	ElementIDNeighborReport:                    "Neighbor Report",
	ElementIDRCPI:                              "RCPI",
	ElementIDMDE:                               "Mobility Domain",
	ElementIDFTE:                               "Fast BSS Transition",
	ElementIDTimeoutInterval:                   "Timeout Interval",
	ElementIDRICData:                           "RIC Data",
	ElementIDDSERegisteredLocation:             "DSE Registered Location",
	ElementIDSupportedOperatingClasses:         "Supported Operating Classes",
	ElementIDExtendedChannelSwitchAnnouncement: "Extended Channel Switch Announcement",
	ElementIDHTOperation:                       "HT Operation",
	ElementIDSecondaryChannelOffset:            "Secondary Channel Offset",
	ElementIDBSSAverageAccessDelay:             "BSS Average Access Delay",
	ElementIDAntenna:                           "Antenna",
	ElementIDRSNI:                              "RSNI",
	ElementIDMeasurementPilotTransmission:      "Measurement Pilot Transmission",
	ElementIDBSSAvailableAdmissionCapacity:     "BSS Available Admission Capacity",
	ElementIDBSSACAccessDelay:                  "BSS AC Access Delay",
	ElementIDTimeAdvertisement:                 "Time Advertisement",
	ElementIDRMEnabledCapabilities:             "RM Enabled Capabilities",
	ElementIDMultipleBSSID:                     "Multiple BSSID",
	ElementIDOverlappingBSSScanParameters:      "Overlapping BSS Scan Parameters",
	ElementIDRICDescriptor:                     "RIC Descriptor",
	ElementIDManagementMIC:                     "Management MIC",
	ElementIDEventRequest:                      "Event Request",
	ElementIDEventReport:                       "Event Report",
	ElementIDDiagnosticRequest:                 "Diagnostic Request",
	ElementIDDiagnosticReport:                  "Diagnostic Report",
	ElementIDLocationParameters:                "Location Parameters",
	ElementIDNontransmittedBSSIDCapability:     "Nontransmitted BSSID Capability",
	ElementIDSSIDList:                          "SSID List",
	ElementIDFMSDescriptor:                     "FMS Descriptor",
	ElementIDFMSRequest:                        "FMS Request",
	ElementIDFMSResponse:                       "FMS Response",
	ElementIDQoSTrafficCapability:              "QoS Traffic Capability",
	ElementIDBSSMaxIdlePeriod:                  "BSS Max Idle Period",
	ElementIDTFSRequest:                        "TFS Request",
	ElementIDTFSResponse:                       "TFS Response",
	ElementIDTIMBroadcastRequest:               "TIM Broadcast Request",
	ElementIDTIMBroadcastResponse:              "TIM Broadcast Response",
	ElementIDCollocatedInterferenceReport:      "Collocated Interference Report",
	ElementIDChannelUsage:                      "Channel Usage",
	ElementIDTimeZone:                          "Time Zone",
	ElementIDDMSRequest:                        "DMS Request",
	ElementIDDMSResponse:                       "DMS Response",
	ElementIDLinkIdentifier:                    " Link Identifier",
	ElementIDWakeupSchedule:                    "Wakeup Schedule",
	ElementIDChannelSwitchTiming:               "Channel Switch Timing",
	ElementIDPTIControl:                        "PTI Control",
	ElementIDTPUBufferStatus:                   "TPU Buffer Status",
	ElementIDInterworking:                      "Interworking",
	ElementIDAdvertisementProtocol:             "Advertisement Protocol",
	ElementIDExpeditedBandwidthRequest:         "Expedited Bandwidth Request",
	ElementIDQoSMapSet:                         "QoS Map Set",
	ElementIDRoamingConsortium:                 "Roaming Consortium",
	ElementIDEmergencyAlertIdentifier:          "Emergency Alert Identifier",
	ElementIDMeshConfiguration:                 "Mesh Configuration",
	ElementIDMeshID:                            "Mesh ID",
	ElementIDMeshLinkMetricReport:              "Mesh Link Metric Report",
	ElementIDCongestionNotification:            "Congestion Notification",
	ElementIDMeshPeeringManagement:             "Mesh Peering Management",
	ElementIDMeshChannelSwitchParameters:       "Mesh Channel Switch Parameters",
	ElementIDMeshAwakeWindow:                   "Mesh Awake Window",
	ElementIDBeaconTiming:                      "Beacon Timing",
	ElementIDMCCAOPSetupRequest:                "MCCAOP Setup Request",
	ElementIDMCCAOPSetupReply:                  "MCCAOP Setup Reply",
	ElementIDMCCAOPAdvertisement:               "MCCAOP Advertisement",
	ElementIDMCCAOPTeardown:                    "MCCAOP Teardown",
	ElementIDGANN:                              "GANN",
	ElementIDRANN:                              "RANN",
	ElementIDExtendedCapabilities:              "Extended Capabilities",
	ElementIDPREQ:                              "PREQ",
	ElementIDPREP:                              "PREP",
	ElementIDPERR:                              "PERR",
	ElementIDPXU:                               "PXU",
	ElementIDPXUC:                              "PXUC",
	ElementIDAuthenticatedMeshPeeringExchange:  "Authenticated Mesh Peering Exchange",
	ElementIDMIC:                               "MIC",
	ElementIDDestinationURI:                    "Destination URI",
	ElementIDUAPSDCoexistence:                  "U-APSD Coexistence",
	ElementIDMCCAOPAdvertisementOverview:       "MCCAOP Advertisement Overview",
	ElementIDVendorSpecific:                    "Vendor Specific",
}

func (m ElementID) String() string {
	if name, ok := elementIDNames[m]; ok {
		return name
	} else {
		return "ElementID(" + strconv.Itoa(int(m)) + ")"
	}
}
