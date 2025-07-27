# LAN 3-Tier Enterprise Architecture

## Network Diagram
### Figure 2-1. Illustration of a three-tier network topology with the main site (A) and other sites (B, C, D and E, respectively) in the cloud, showing placement of appliances and security devices.
<img width="1000" src="https://github.com/user-attachments/assets/8c3e27e8-c127-4455-b817-d87c72956a20" />

- The diagram shows a security implementation with essential appliances and devices within a partial mesh topology.
- The main site (A) includes a network edge with an SD-WAN edge router, next-generation firewall (NGFW), and core switches.
- Subnets and VLANs segment the network traffic, allowing controlled access for staff, guests, IoT, BYOD, and management.
- Staff and guests use designated SSIDs; management has full network access for administrative tasks.
- CCTV and VoIP run on separate VLANs for security and Quality of Service (QoS).
- Wi-Fi 6 access points (APs), centrally managed by a wireless controller, provide up to 6 Gbps bandwidth throughout the main site.
- Public servers reside in a DMZ, while other servers are local to the trusted user segment.
- The topology includes a local SDN data centre supporting iSCSI SAN technology.
- Partial mesh WAN topology offers better redundancy than hub-and-spoke, with lower cost than full mesh, balancing efficiency and cost-effectiveness for the organisation.

Figure 2-1 illustrates the logical architecture providing foundational network services including tiered LAN connectivity, wireless and wired infrastructure for multimedia, IP multicast for efficient data distribution, and wired access for staff and management.

To ensure a robust, reliable, high-performance, and future-proof LAN supporting the scenario in task 1, these components are used:
- **Wireless LAN – Cisco Meraki MR57**  
  Wi-Fi 6 APs for high-density wireless coverage at the main site; supports mGig uplinks and adaptive policy.  
- **Access Switches – Cisco Catalyst 9300X**  
  Layer 3 with adaptive policy, physical stacking, 40G uplinks, 208 Gbps switching capacity.  
- **Core & Distribution Switches – Cisco Catalyst 9500X**  
  Secure segmentation, 6.4 Tbps capacity, 100G uplinks.  
- **SD-WAN Edge Routers – Cisco ASR 1002-HX**  
  Pay-as-you-grow (44–100 Gbps), ideal for medium-large enterprises, supports WAN aggregation via partial mesh SD-WAN topology.

## Assumptions from Appendix B Scenario

- Wi-Fi 6 roaming across main site (A) with controllers and APs; internet bandwidth of 6 Gbps.  
- VLANs span multiple areas within main site (A).  
- SSID and VLAN assignments:  
  - Staff SSID → VLAN 80 (CoA VLAN 90 via Cisco ISE)  
  - Guest SSID → VLAN 90  
  - BYOD SSID → VLAN 100 (CoA VLAN 90 via Cisco ISE)  
  - IoT SSID → VLAN 110  
- Access switch uplinks use trunk mode; native VLAN = VLAN 1 (Management VLAN).  
- Access layer switches operate in Layer 2 mode (no SVIs or DHCP).  
- C9300X and C9500X switches stacked for redundancy.  
- STP root placed at distribution and core layers to prevent loops and improve performance.  
- Distribution/collapsed-core uplinks configured to handle VLAN traffic efficiently using management VLAN 1.  
- VLAN SVIs hosted and monitored on the core layer.  
- Network devices receive fixed IPs from management VLAN DHCP pool; default gateway: 10.0.1.1.  
- All infrastructure connections include fault tolerance for redundancy.  
- STP BPDU guard enabled on trunk ports (native VLAN 1) at acces













