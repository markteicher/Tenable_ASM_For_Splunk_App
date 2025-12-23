# Tenable ASM For Splunk App
Tenable Attack Surface Management For Splunk App


## ⚠️ Disclaimer

This Splunk App is **not an official Tenable product**.

Use of this software is **not covered** by any license, warranty, or support agreement you may have with Tenable.  
All functionality is implemented independently using publicly available Tenable Attack Surface Management API Documentation.



# Directory Structure

tenable_attack_surface_management/
├── appserver/
│   └── static/
│       ├── appIcon.png
│       ├── appIcon_2x.png
│       ├── appIconAlt.png
│       └── appIconAlt_2x.png
│
├── bin/
│   ├── tenable_asm_modinput.py
│   └── lib/
│       ├── __init__.py
│       ├── asm_client.py
│       ├── asm_auth.py
│       ├── asm_paging.py
│       ├── asm_logging.py
│       └── asm_time.py
│
├── default/
│   ├── app.conf
│   ├── inputs.conf
│   ├── props.conf
│   ├── savedsearches.conf
│   ├── web.conf
│   └── setup.xml
│
├── metadata/
│   └── default.meta
│
├── ui/
│   ├── nav/
│   │   └── default.xml
│   └── views/
│       ├── asm_overview.xml
│       ├── asm_inventory.xml
│       ├── asm_assets.xml
│       ├── asm_sources.xml
│       ├── asm_tags.xml
│       ├── asm_suggestions.xml
│       ├── asm_subscriptions.xml
│       ├── asm_text_records.xml
│       ├── asm_user_action_logs.xml
│       ├── asm_reporting.xml
│       ├── asm_operations.xml
│       └── asm_administration.xml
│
└── README/
    ├── README.md
    └── INSTALL.md
    └── UPGRADE.md
  
