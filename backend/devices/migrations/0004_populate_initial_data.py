# Generated migration - Populate initial vendors and device types
from django.db import migrations


def populate_initial_data(apps, schema_editor):
    """Create initial vendors and device types"""
    Vendor = apps.get_model('devices', 'Vendor')
    DeviceType = apps.get_model('devices', 'DeviceType')

    # Create Device Types (predefined)
    device_types = [
        {
            'name': 'Router',
            'slug': 'router',
            'description': 'Network router device',
            'icon': 'router',
            'is_predefined': True,
        },
        {
            'name': 'Switch',
            'slug': 'switch',
            'description': 'Network switch device',
            'icon': 'switch',
            'is_predefined': True,
        },
        {
            'name': 'Firewall',
            'slug': 'firewall',
            'description': 'Network firewall device',
            'icon': 'firewall',
            'is_predefined': True,
        },
        {
            'name': 'Server',
            'slug': 'server',
            'description': 'Server device',
            'icon': 'server',
            'is_predefined': False,
        },
        {
            'name': 'Access Point',
            'slug': 'access-point',
            'description': 'Wireless access point',
            'icon': 'wifi',
            'is_predefined': False,
        },
    ]

    for dt_data in device_types:
        DeviceType.objects.get_or_create(
            slug=dt_data['slug'],
            defaults=dt_data
        )

    # Create Vendors (predefined)
    vendors = [
        {
            'name': 'Cisco',
            'slug': 'cisco',
            'description': 'Cisco Systems network equipment',
            'is_predefined': True,
            'backup_commands': {
                'setup': ['terminal length 0'],
                'backup': 'show running-config',
                'enable_mode': True,
                'logout': ['end', 'exit']
            }
        },
        {
            'name': 'Huawei',
            'slug': 'huawei',
            'description': 'Huawei network equipment (VRP)',
            'is_predefined': True,
            'backup_commands': {
                'setup': ['screen-length 0 temporary'],
                'backup': 'display current-configuration',
                'enable_mode': False,
                'logout': ['quit', 'quit']
            }
        },
        {
            'name': 'MikroTik',
            'slug': 'mikrotik',
            'description': 'MikroTik RouterOS devices',
            'is_predefined': True,
            'backup_commands': {
                'setup': [],
                'backup': '/export',
                'enable_mode': False,
                'logout': ['quit']
            }
        },
        {
            'name': 'Fortinet',
            'slug': 'fortinet',
            'description': 'Fortinet FortiGate firewalls',
            'is_predefined': True,
            'backup_commands': {
                'setup': ['config system console', 'set output standard', 'end'],
                'backup': 'show full-configuration',
                'enable_mode': False,
                'logout': ['end', 'exit']
            }
        },
        {
            'name': 'Juniper',
            'slug': 'juniper',
            'description': 'Juniper Networks JunOS devices',
            'is_predefined': True,
            'backup_commands': {
                'setup': ['set cli screen-length 0'],
                'backup': 'show configuration',
                'enable_mode': False,
                'logout': ['end', 'exit']
            }
        },
        {
            'name': 'HP/HPE',
            'slug': 'hp',
            'description': 'HP/HPE Comware network equipment',
            'is_predefined': True,
            'backup_commands': {
                'setup': ['screen-length disable'],
                'backup': 'display current-configuration',
                'enable_mode': False,
                'logout': ['quit', 'quit']
            }
        },
        {
            'name': 'TP-Link',
            'slug': 'tplink',
            'description': 'TP-Link network switches and routers',
            'is_predefined': True,
            'backup_commands': {
                'setup': ['terminal length 0'],
                'backup': 'show running-config',
                'enable_mode': True,
                'logout': ['end', 'exit']
            }
        },
        {
            'name': 'Aruba',
            'slug': 'aruba',
            'description': 'Aruba Networks (HPE) wireless and switching',
            'is_predefined': True,
            'backup_commands': {
                'setup': ['no paging'],
                'backup': 'show running-config',
                'enable_mode': True,
                'logout': ['end', 'exit']
            }
        },
        {
            'name': 'Grandstream',
            'slug': 'grandstream',
            'description': 'Grandstream VoIP devices and PBX',
            'is_predefined': True,
            'backup_commands': {
                'setup': [],
                'backup': 'show running-config',
                'enable_mode': False,
                'logout': ['exit']
            }
        },
        {
            'name': 'Arista',
            'slug': 'arista',
            'description': 'Arista EOS switches',
            'is_predefined': True,
            'backup_commands': {
                'setup': ['terminal length 0'],
                'backup': 'show running-config',
                'enable_mode': True,
                'logout': ['end', 'exit']
            }
        },
        {
            'name': 'Dell',
            'slug': 'dell',
            'description': 'Dell OS10 network switches',
            'is_predefined': True,
            'backup_commands': {
                'setup': ['terminal length 0'],
                'backup': 'show running-configuration',
                'enable_mode': True,
                'logout': ['end', 'exit']
            }
        },
        {
            'name': 'Eltex',
            'slug': 'eltex',
            'description': 'Eltex network equipment (MES/ESR series)',
            'is_predefined': True,
            'backup_commands': {
                'setup': ['terminal datadump'],
                'backup': 'show running-config',
                'enable_mode': True,
                'logout': ['end', 'exit']
            }
        },
        {
            'name': 'Generic',
            'slug': 'generic',
            'description': 'Generic network device (SSH/Telnet)',
            'is_predefined': True,
            'backup_commands': {
                'setup': [],
                'backup': 'show running-config',
                'enable_mode': False,
                'logout': ['end', 'exit']
            }
        },
    ]

    for vendor_data in vendors:
        Vendor.objects.get_or_create(
            slug=vendor_data['slug'],
            defaults=vendor_data
        )

    print(f"Created {len(device_types)} device types and {len(vendors)} vendors")


class Migration(migrations.Migration):

    dependencies = [
        ('devices', '0003_add_is_predefined_to_devicetype'),
    ]

    operations = [
        migrations.RunPython(populate_initial_data, migrations.RunPython.noop),
    ]
