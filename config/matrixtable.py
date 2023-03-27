#!/usr/bin/env python3

Matrices = {
  'Enterprise': {
    'name': 'MITRE ATT&CK® Matrix for Enterprise',
    'description': 'The Matrix contains information for the following platforms: Windows, macOS, Linux, PRE, Azure AD, Office 365, Google Workspace, SaaS, IaaS, Network, Containers.',
    'file': 'enterprise-attack.json',
    'type': 'json',
    'url': 'https://raw.githubusercontent.com/mitre/cti/master/'
           'enterprise-attack/enterprise-attack.json',
  },
  'ICS': {
    'name': 'MITRE ATT&CK® Matrix for ICS',
    'description': 'ATT&CK for ICS is a knowledge base useful for describing the actions an adversary may take while operating within an ICS network. The knowledge base can be used to better characterize and describe post-compromise adversary behavior.',
    'file': 'ics-attack.json',
    'type': 'json',
    'url': 'https://raw.githubusercontent.com/mitre/cti/master/'
           'ics-attack/ics-attack.json',
  },
  'PRE': {
    'name': 'MITRE ATT&CK® Matrix for PRE',
    'description': 'MITRE ATT&CK® Matrix for Enterprise, covering PREparatory techniques.',
    'file': 'pre-attack.json',
    'type': 'json',
    'url': 'https://raw.githubusercontent.com/mitre/cti/master/'
           'pre-attack/pre-attack.json',
  },
  'Mobile': {
    'name': 'MITRE ATT&CK® Matrix for Mobile',
    'description': 'MITRE ATT&CK Matrix for Android and iOS.',
    'file': 'mobile-attack.json',
    'type': 'json',
    'url': 'https://raw.githubusercontent.com/mitre/cti/master/'
           'mobile-attack/mobile-attack.json',
  },
  'FiGHT': {
    'name': 'MITRE ATT&CK Matrix for 5G (telecommunications) systems',
    'description': 'FiGHT™ (5G Hierarchy of Threats) is a knowledge base of adversary Tactics and Techniques for 5G systems. FiGHT™ consists of three types of Techniques: theoretical, proof of concept (PoC), and observed',
    'file': 'fight.yaml',
    'type': 'yaml',
    'url': 'https://raw.githubusercontent.com/mitre/FiGHT/main/fight.yaml',
  },
}

if __name__ == '__main__':
    print("What are you doing..?! Don't run this file!")
