using System;

namespace Wifi
{
    class Program
    {
        static void Main(string[] args)
        {
            [DllImport("Wlanapi.dll", SetLastError = true, CharSet = CharSet.Auto)]
            //public static extern int WlanEnumInterfaces(IntPtr hClientHandle, IntPtr pReserved, out WLAN_INTERFACE_INFO_LIST ppInterfaceList);
            public static extern int WlanEnumInterfaces(IntPtr hClientHandle, IntPtr pReserved, [Out, MarshalAs(UnmanagedType.SysUInt)] out IntPtr ppInterfaceList);

            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
            public struct WLAN_INTERFACE_INFO_LIST
        {
            public int dwNumberOfItems;
            public int dwIndex;
            public WLAN_INTERFACE_INFO[] InterfaceInfo;
            public WLAN_INTERFACE_INFO_LIST(IntPtr pList)
            {
                dwNumberOfItems = Marshal.ReadInt32(pList, 0);
                dwIndex = Marshal.ReadInt32(pList, 4);
                InterfaceInfo = new WLAN_INTERFACE_INFO[dwNumberOfItems];
                for (int i = 0; i < dwNumberOfItems; i++)
                {
                    IntPtr pItemList = new IntPtr(pList.ToInt32() + (i * Marshal.SizeOf(typeof(WLAN_INTERFACE_INFO))) + 8);
                    WLAN_INTERFACE_INFO wii = new WLAN_INTERFACE_INFO();
                    wii = (WLAN_INTERFACE_INFO)Marshal.PtrToStructure(pItemList, typeof(WLAN_INTERFACE_INFO));
                    InterfaceInfo[i] = wii;
                }
            }
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct WLAN_INTERFACE_INFO
        {
            public Guid InterfaceGuid;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = WLAN_MAX_NAME_LENGTH)]
            public string strInterfaceDescription;
            public WLAN_INTERFACE_STATE isState;
        }

        public const int WLAN_MAX_NAME_LENGTH = 256;
        public enum WLAN_INTERFACE_STATE
        {
            wlan_interface_state_not_ready,
            wlan_interface_state_connected,
            wlan_interface_state_ad_hoc_network_formed,
            wlan_interface_state_disconnecting,
            wlan_interface_state_disconnected,
            wlan_interface_state_associating,
            wlan_interface_state_discovering,
            wlan_interface_state_authenticating
        }

        [DllImport("Wlanapi.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern int WlanOpenHandle(int dwClientVersion, IntPtr pReserved, out int pdwNegotiatedVersion, out IntPtr phClientHandle);

        public const int WLAN_API_VERSION_1_0 = 0x00000001;
        public const int WLAN_API_VERSION_2_0 = 0x00000002;

        [DllImport("Wlanapi.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern int WlanCloseHandle(IntPtr hClientHandle, IntPtr pReserved);

        [DllImport("Wlanapi.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern void WlanFreeMemory(IntPtr pMemory);

        [DllImport("Wlanapi.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern int WlanRegisterNotification(IntPtr hClientHandle, int dwNotifSource, bool bIgnoreDuplicate, WlanNotificationCallback funcCallback,
            IntPtr pCallbackContext, IntPtr pReserved, out int pdwPrevNotifSource);

        public delegate void WlanNotificationCallback(ref WLAN_NOTIFICATION_DATA pData, IntPtr pVoid);

        [StructLayoutAttribute(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct WLAN_NOTIFICATION_DATA
        {
            public int NotificationSource;
            public int NotificationCode;
            public Guid InterfaceGuid;
            public int dwDataSize;
            public IntPtr pData;
        }

        public const int WLAN_NOTIFICATION_SOURCE_NONE = 0;
        public const int WLAN_NOTIFICATION_SOURCE_ALL = 0X0000FFFF;

        public enum WLAN_NOTIFICATION_ACM
        {
            wlan_notification_acm_start = 0X00000000,
            wlan_notification_acm_autoconf_enabled,
            wlan_notification_acm_autoconf_disabled,
            wlan_notification_acm_background_scan_enabled,
            wlan_notification_acm_background_scan_disabled,
            wlan_notification_acm_bss_type_change,
            wlan_notification_acm_power_setting_change,
            wlan_notification_acm_scan_complete,
            wlan_notification_acm_scan_fail,
            wlan_notification_acm_connection_start,
            wlan_notification_acm_connection_complete,
            wlan_notification_acm_connection_attempt_fail,
            wlan_notification_acm_filter_list_change,
            wlan_notification_acm_interface_arrival,
            wlan_notification_acm_interface_removal,
            wlan_notification_acm_profile_change,
            wlan_notification_acm_profile_name_change,
            wlan_notification_acm_profiles_exhausted,
            wlan_notification_acm_network_not_available,
            wlan_notification_acm_network_available,
            wlan_notification_acm_disconnecting,
            wlan_notification_acm_disconnected,
            wlan_notification_acm_adhoc_network_state_change,
            wlan_notification_acm_profile_unblocked,
            wlan_notification_acm_screen_power_change,
            wlan_notification_acm_profile_blocked,
            wlan_notification_acm_scan_list_refresh,
            wlan_notification_acm_operational_state_change,
            wlan_notification_acm_end
        }

        [DllImport("Wlanapi.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern int WlanScan(IntPtr hClientHandle, ref Guid pInterfaceGuid, IntPtr pDot11Ssid, IntPtr pIeData, IntPtr pReserved);

        [DllImport("Wlanapi.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern int WlanGetAvailableNetworkList(IntPtr hClientHandle, ref Guid pInterfaceGuid, int dwFlags, IntPtr pReserved, out IntPtr ppAvailableNetworkList);

        // flags that control the list returned by WlanGetAvailableNetworkList
        // include all ad hoc network profiles in the available network list, regardless they are visible or not
        public const int WLAN_AVAILABLE_NETWORK_INCLUDE_ALL_ADHOC_PROFILES = 0x00000001;
        // include all hidden network profiles in the available network list, regardless they are visible or not
        public const int WLAN_AVAILABLE_NETWORK_INCLUDE_ALL_MANUAL_HIDDEN_PROFILES = 0x00000002;

        [StructLayout(LayoutKind.Sequential)]
        public struct WLAN_AVAILABLE_NETWORK_LIST
        {
            public uint dwNumberOfItems;
            public uint dwIndex;
            public WLAN_AVAILABLE_NETWORK[] Network;

            public WLAN_AVAILABLE_NETWORK_LIST(IntPtr ppAvailableNetworkList)
            {
                dwNumberOfItems = (uint)Marshal.ReadInt32(ppAvailableNetworkList, 0);
                dwIndex = (uint)Marshal.ReadInt32(ppAvailableNetworkList, 4 /* Offset for dwNumberOfItems */);
                Network = new WLAN_AVAILABLE_NETWORK[dwNumberOfItems];

                for (int i = 0; i < dwNumberOfItems; i++)
                {
                    var availableNetwork = new IntPtr(ppAvailableNetworkList.ToInt64()
                        + 8 /* Offset for dwNumberOfItems and dwIndex */
                        + (Marshal.SizeOf(typeof(WLAN_AVAILABLE_NETWORK)) * i) /* Offset for preceding items */);

                    Network[i] = (WLAN_AVAILABLE_NETWORK)Marshal.PtrToStructure(availableNetwork, typeof(WLAN_AVAILABLE_NETWORK));
                }
            }
        }

        [StructLayoutAttribute(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct WLAN_AVAILABLE_NETWORK
        {
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = WLAN_MAX_NAME_LENGTH)]
            public string strProfileName;
            public DOT11_SSID dot11Ssid;
            public DOT11_BSS_TYPE dot11BssType;
            public uint uNumberOfBssids;
            public bool bNetworkConnectable;
            public int wlanNotConnectableReason;
            public uint uNumberOfPhyTypes;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = WLAN_MAX_PHY_TYPE_NUMBER)]
            public DOT11_PHY_TYPE[] dot11PhyTypes;
            // bMorePhyTypes is set to TRUE if the PHY types for the network
            // exceeds WLAN_MAX_PHY_TYPE_NUMBER.
            // In this case, uNumerOfPhyTypes is WLAN_MAX_PHY_TYPE_NUMBER and the
            // first WLAN_MAX_PHY_TYPE_NUMBER PHY types are returned.
            public bool bMorePhyTypes;
            public uint wlanSignalQuality;
            public bool bSecurityEnabled;
            public DOT11_AUTH_ALGORITHM dot11DefaultAuthAlgorithm;
            public DOT11_CIPHER_ALGORITHM dot11DefaultCipherAlgorithm;
            public int dwFlags;
            public int dwReserved;
        }

        public const int DOT11_SSID_MAX_LENGTH = 32;

        [StructLayoutAttribute(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct DOT11_SSID
        {
            public uint uSSIDLength;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = DOT11_SSID_MAX_LENGTH)]
            public byte[] ucSSID;

            /// <summary>
            /// Returns the byte array of SSID.
            /// </summary>
            /// <returns>Byte array</returns>
            public byte[] ToBytes() => ucSSID?.Take((int)uSSIDLength).ToArray();

            private static Lazy<Encoding> _encoding = new Lazy<Encoding>(() =>
                Encoding.GetEncoding(65001, // UTF-8 code page
                    EncoderFallback.ReplacementFallback,
                    DecoderFallback.ExceptionFallback));

            /// <summary>
            /// Returns the UTF-8 string representation of SSID
            /// </summary>
            /// <returns>UTF-8 string if successfully converted the byte array of SSID. Null if failed.</returns>
            public override string ToString()
            {
                if (ucSSID != null)
                {
                    try
                    {
                        return _encoding.Value.GetString(ToBytes());
                    }
                    catch (DecoderFallbackException)
                    { }
                }
                return null;
            }
        }

        public enum DOT11_BSS_TYPE
        {
            dot11_BSS_type_infrastructure = 1,
            dot11_BSS_type_independent = 2,
            dot11_BSS_type_any = 3
        }

        public const int WLAN_MAX_PHY_TYPE_NUMBER = 8;

        public enum DOT11_PHY_TYPE
        {
            dot11_phy_type_unknown = 0,
            dot11_phy_type_any = dot11_phy_type_unknown,
            dot11_phy_type_fhss = 1,
            dot11_phy_type_dsss = 2,
            dot11_phy_type_irbaseband = 3,
            dot11_phy_type_ofdm = 4,
            dot11_phy_type_hrdsss = 5,
            dot11_phy_type_erp = 6,
            dot11_phy_type_ht = 7,
            dot11_phy_type_vht = 8,
            dot11_phy_type_dmg = 9,
            dot11_phy_type_IHV_start = unchecked((int)0x80000000),
            dot11_phy_type_IHV_end = unchecked((int)0xffffffff)
        }

        public enum DOT11_AUTH_ALGORITHM
        {
            DOT11_AUTH_ALGO_80211_OPEN = 1,
            DOT11_AUTH_ALGO_80211_SHARED_KEY = 2,
            DOT11_AUTH_ALGO_WPA = 3,
            DOT11_AUTH_ALGO_WPA_PSK = 4,
            DOT11_AUTH_ALGO_WPA_NONE = 5,               // used in NatSTA only
            DOT11_AUTH_ALGO_RSNA = 6,
            DOT11_AUTH_ALGO_RSNA_PSK = 7,
            DOT11_AUTH_ALGO_IHV_START = unchecked((int)0x80000000),
            DOT11_AUTH_ALGO_IHV_END = unchecked((int)0xffffffff)
        }

        public enum DOT11_CIPHER_ALGORITHM
        {
            DOT11_CIPHER_ALGO_NONE = 0x00,
            DOT11_CIPHER_ALGO_WEP40 = 0x01,
            DOT11_CIPHER_ALGO_TKIP = 0x02,
            DOT11_CIPHER_ALGO_CCMP = 0x04,
            DOT11_CIPHER_ALGO_WEP104 = 0x05,
            DOT11_CIPHER_ALGO_BIP = 0x06,
            DOT11_CIPHER_ALGO_GCMP = 0x08,
            DOT11_CIPHER_ALGO_WPA_USE_GROUP = 0x100,
            DOT11_CIPHER_ALGO_RSN_USE_GROUP = 0x100,
            DOT11_CIPHER_ALGO_WEP = 0x101,
            DOT11_CIPHER_ALGO_IHV_START = unchecked((int)0x80000000),
            DOT11_CIPHER_ALGO_IHV_END = unchecked((int)0xffffffff)
        }

        // available network flags
        public const int WLAN_AVAILABLE_NETWORK_CONNECTED = 0x00000001;  // This network is currently connected
        public const int WLAN_AVAILABLE_NETWORK_HAS_PROFILE = 0x00000002;  // There is a profile for this network
        public const int WLAN_AVAILABLE_NETWORK_CONSOLE_USER_PROFILE = 0x00000004;  // The profile is the active console user's per user profile
        public const int WLAN_AVAILABLE_NETWORK_INTERWORKING_SUPPORTED = 0x00000008;  // Interworking is supported
        public const int WLAN_AVAILABLE_NETWORK_HOTSPOT2_ENABLED = 0x00000010;  // Hotspot2 is enabled
        public const int WLAN_AVAILABLE_NETWORK_ANQP_SUPPORTED = 0x00000020;  // ANQP is supported
        public const int WLAN_AVAILABLE_NETWORK_HOTSPOT2_DOMAIN = 0x00000040;  // Domain network 
        public const int WLAN_AVAILABLE_NETWORK_HOTSPOT2_ROAMING = 0x00000080;  // Roaming network
        public const int WLAN_AVAILABLE_NETWORK_AUTO_CONNECT_FAILED = 0x00000100;  // This network failed to connect

        [DllImport("Wlanapi.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern int WlanGetProfile(IntPtr hClientHandle, ref Guid pInterfaceGuid, string strProfileName, IntPtr pReserved, out string pstrProfileXml, out int pdwFlags, out int pdwGrantedAccess);

        [DllImport("Wlanapi.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern int WlanConnect(IntPtr hClientHandle, ref Guid pInterfaceGuid, ref WLAN_CONNECTION_PARAMETERS pConnectionParameters, IntPtr pReserved);

        [StructLayoutAttribute(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct WLAN_CONNECTION_PARAMETERS
        {
            public WLAN_CONNECTION_MODE wlanConnectionMode;
            public string strProfile;
            public IntPtr pDot11Ssid; // PDOT11_SSID
                                      // public DOT11_SSID pDot11Ssid; 
            public IntPtr pDesiredBssidList;
            public DOT11_BSS_TYPE dot11BssType;
            public int dwFlags;
        }

        public enum WLAN_CONNECTION_MODE
        {
            wlan_connection_mode_profile,
            wlan_connection_mode_temporary_profile,
            wlan_connection_mode_discovery_secure,
            wlan_connection_mode_discovery_unsecure,
            wlan_connection_mode_auto,
            wlan_connection_mode_invalid
        }

        static bool bDone = false;
        static WlanNotificationCallback WlanNotificationProc = null;
        public static void WlanNotification(ref WLAN_NOTIFICATION_DATA pData, IntPtr pVoid)
        {
            if ((WLAN_NOTIFICATION_ACM)pData.NotificationCode == WLAN_NOTIFICATION_ACM.wlan_notification_acm_scan_complete)
            {
                bDone = true;
            }
            else if ((WLAN_NOTIFICATION_ACM)pData.NotificationCode == WLAN_NOTIFICATION_ACM.wlan_notification_acm_scan_fail)
            {
                //printf("Scanning failed with error: %x\n", wlanNotifData->pData);
                bDone = true;
            }
        }
    }
    }
}
