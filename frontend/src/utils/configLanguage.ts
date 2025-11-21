/**
 * Utility to determine Monaco Editor language based on device vendor
 * Monaco Editor doesn't have built-in support for network device configs,
 * so we use closest available languages for basic syntax highlighting
 */

export const getConfigLanguage = (vendorSlug: string): string => {
  const vendorMap: Record<string, string> = {
    // Cisco uses IOS-like syntax - closest to shell/bash
    'cisco': 'shell',

    // Huawei VRP is similar to Cisco
    'huawei': 'shell',

    // Juniper uses XML-like structured config
    'juniper': 'xml',

    // MikroTik RouterOS has scripting syntax
    'mikrotik': 'shell',

    // HP/Aruba switches
    'hp': 'shell',
    'aruba': 'shell',

    // Fortinet FortiGate
    'fortinet': 'shell',
    'fortigate': 'shell',

    // TP-Link
    'tplink': 'shell',

    // Grandstream
    'grandstream': 'shell',

    // Arista
    'arista': 'shell',

    // Dell
    'dell': 'shell',

    // Palo Alto
    'paloalto': 'xml',

    // Default fallback
    'default': 'plaintext'
  };

  return vendorMap[vendorSlug?.toLowerCase()] || vendorMap['default'];
};

/**
 * Get human-readable language name for display
 */
export const getConfigLanguageName = (vendorSlug: string): string => {
  const nameMap: Record<string, string> = {
    'cisco': 'Cisco IOS',
    'huawei': 'Huawei VRP',
    'juniper': 'Juniper JunOS',
    'mikrotik': 'MikroTik RouterOS',
    'hp': 'HP/HPE Comware',
    'aruba': 'Aruba ArubaOS',
    'fortinet': 'FortiOS',
    'fortigate': 'FortiOS',
    'tplink': 'TP-Link',
    'grandstream': 'Grandstream',
    'arista': 'Arista EOS',
    'dell': 'Dell OS10',
    'paloalto': 'PAN-OS',
    'default': 'Plain Text'
  };

  return nameMap[vendorSlug?.toLowerCase()] || nameMap['default'];
};
