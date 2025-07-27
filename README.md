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

To deliver a robust, high-performance, future-proof LAN for the scenario in task 1, the following components are used:

- **Wireless LAN – Cisco Meraki MR57:** Wi-Fi 6 for high-density APs at the main site, supports mGig uplinks and adaptive policy. [1] [5]  
- **Access Switches – Cisco Catalyst 9300X:** Layer 3, adaptive policy, physical stacking, 40G uplinks, 208 Gbps switching capacity. [1] [6] [19]  
- **Core & Distribution Switches – Cisco Catalyst 9500X:** Secure segmentation, 6.4 Tbps capacity, 100G uplinks. [1] [7] [19]  
- **SD-WAN Edge Routers – Cisco ASR 1002-HX:** Pay-as-you-grow (44-100 Gbps), ideal for medium-large enterprises, supports WAN aggregation via partial mesh SD-WAN topology. [1] [8] [20]

Assumptions from Appendix B scenario:  
- Wi-Fi 6 roaming across accommodation at main site (A) with wireless controllers/APs and 6 Gbps internet bandwidth.  
- VLANs span multiple areas at main site (A).  
- Staff SSID broadcasts everywhere, assigned VLAN 80; CoA VLAN 90 via Cisco ISE. [16]  
- Guest SSID assigned VLAN 90.  
- BYOD SSID assigned VLAN 100; CoA VLAN 90 via Cisco ISE.  
- IoT SSID assigned VLAN 110.  
- Access switch uplinks in trunk mode; native VLAN = VLAN 1 (Management VLAN).  
- Access switches run Layer 2 only (no SVIs or DHCP).  
- C9300X and C9500X switches stacked for redundancy.  
- STP root at distribution/core layers to prevent loops and optimise network performance.  
- Distribution/collapsed-core uplinks configured with management VLAN (VLAN 1) trunk to efficiently handle VLAN traffic.  
- VLAN SVIs hosted and monitored on core layer for efficient traffic management. [17]  
- Network devices assigned fixed IPs from management VLAN DHCP pool; default gateway 10.0.1.1.  
- All network connections have fault tolerance for redundancy and service uptime.  
- STP BPDU guard enabled on access layer trunk ports (native VLAN 1) to block unauthorised devices.

## Firewall

Firewalls operate at the core layer, providing essential network security through components like packet filters, proxy servers, authentication systems, and NAT software. Some firewalls encrypt traffic, establish VPNs, and include routing capabilities. They restrict unauthorised access using packet filtering and proxy services to block unwanted traffic, maintaining robust network security.

### Types of Firewalls:
- **Packet Filtering:** Inspects packets based on IP addresses, ports, and protocols.  
  - Pros: Cost-effective, high performance, reliable, filters entire enterprise traffic.  
  - Cons: Does not inspect payload, easily spoofed, limited context, complex ACL management.  
  - Unsuitable for protecting sensitive data like R&D secrets.

- **Circuit-level Gateway:** Monitors TCP handshakes and session initiation messages to verify session authenticity.  
  - Pros: Simple, inexpensive, efficient by processing only requested traffic.  
  - Cons: No application layer monitoring, needs frequent rule updates.  
  - Often paired with application-level gateways for content filtering.

- **Application-level Gateway (Proxy Firewall):** Filters traffic by destination port and inspects packet contents such as HTTP requests.  
  - Pros: Detailed inspection of traffic content, enforces corporate policies.  
  - Cons: Performance impact, costly and resource-intensive, can cause congestion.

- **Stateful Inspection Firewall:** Tracks connection state in real-time, inspecting payload and session state.  
  - Pros: Granular control, thorough inspection, better security than above types.  
  - Cons: Resource-heavy, costly, no authentication capabilities; therefore, unsuitable alone for proposed design.

- **Next-Generation Firewall (NGFW):** Combines packet and stateful inspection with deep packet inspection (DPI), IDPS, VPN, and integration with SIEM systems (e.g., SolarWinds Security Event Manager).  
  - Pros: Comprehensive security across OSI layers, automatic real-time updates, precise packet inspection.  
  - Cons: Requires professional expertise, higher cost.

### NGFW Implementation for Scenario:
- Cisco FirePOWER 4145 NGIPS selected for main site (A) in a partial mesh topology with sites B, C, D, and E across the UK using WAN, leased lines, SD-WAN, and VPN.  
- Designed for large enterprises and data centres, future-proofing the network.  
- Supports targeted rules for efficient packet handling.  
- Essential for regulated organisations and effective when integrated with other security systems.

### Deployment:
- Hardware-based NGFW chosen for the scenario in Appendix B to minimise impact on network performance by offloading processing from other devices.

[1] [9] [10] [11] [12] [13]

## IDPS

An **Intrusion Detection System (IDS)** alerts IT professionals about malicious activity and threats. An **Intrusion Prevention System (IPS)** has similar capabilities but can isolate or shut down compromised network segments to protect confidentiality, integrity, and availability (CIA). For the scenario, both IDS and IPS functions are essential, making combined IDPS solutions highly valuable for meeting end-user requirements.

### Role of IDPS:
- Detects and reports incidents such as DoS attacks and policy violations.  
- Monitors network traffic, identifies suspicious activity, and contains malware.  
- Supports maintaining robust network security.

### Types of IDPS:
- **Network-based:** Monitors traffic via hardware or software sensors across the network; may miss attacks bypassing the network layer.  
- **Host-based:** Installed on devices for granular control over host/application attacks; resource-intensive to deploy.  
- **Wireless:** Monitors wireless networks, similar to network-based but localised to wireless environments.  
- **Hybrid:** Combines the above types, offering comprehensive coverage at higher complexity and cost.

### Recommended Solution:
- A **hybrid IDPS** suits the scenario best, balancing broad protection with scalability and future-proofing.  
- Example appliance: **Cisco FirePOWER 4145 NGIPS**, supporting up to 53 Gbps inspected IDPS throughput, capable of advanced threat detection and blocking.  
- Ideal for a partial mesh WAN topology with five UK sites connected via leased lines, SD-WAN, VPN, and multiple segmented subnets.  
- Though costly (around £100,000), it meets enterprise requirements and ensures network security across all sites.

[28] [29] [30] [31] [32]

## IDPS

An **Intrusion Detection System (IDS)** alerts IT professionals about malicious activity and threats. An **Intrusion Prevention System (IPS)** has similar capabilities but can isolate or shut down compromised network segments to protect confidentiality, integrity, and availability (CIA). For the scenario, both IDS and IPS functions are essential, making combined IDPS solutions highly valuable for meeting end-user requirements.

### Role of IDPS:
- Detects and reports incidents such as DoS attacks and policy violations.  
- Monitors network traffic, identifies suspicious activity, and contains malware.  
- Supports maintaining robust network security.

### Types of IDPS:
- **Network-based:** Monitors traffic via hardware or software sensors across the network; may miss attacks bypassing the network layer.  
- **Host-based:** Installed on devices for granular control over host/application attacks; resource-intensive to deploy.  
- **Wireless:** Monitors wireless networks, similar to network-based but localised to wireless environments.  
- **Hybrid:** Combines the above types, offering comprehensive coverage at higher complexity and cost.

### Recommended Solution:
- A **hybrid IDPS** suits the scenario best, balancing broad protection with scalability and future-proofing.  
- Example appliance: **Cisco FirePOWER 4145 NGIPS**, supporting up to 53 Gbps inspected IDPS throughput, capable of advanced threat detection and blocking.  
- Ideal for a partial mesh WAN topology with five UK sites connected via leased lines, SD-WAN, VPN, and multiple segmented subnets.  
- Though costly (around £100,000), it meets enterprise requirements and ensures network security across all sites.

[28] [29] [30] [31] [32]

## VPN

A **VPN** provides a cost-effective, secure method to connect an organisation and remote users to the enterprise’s private network by encapsulating and encrypting data, combined with authentication to ensure authorised access via secure point-to-point channels.

- In the network design (Figure 2-1), **site-to-site VPN** should be enabled over SD-WAN. For example, VLAN 1 (management subnet) will be used for RADIUS authentication as Cisco Meraki MR57, C9300, and C9500 devices communicate with Cisco ISE via their management IPs.

- **VPN deployment options** include:  
  - *Remote Access VPN:* Connects devices to a VPN gateway; authenticates devices before granting network access; uses IPsec or SSL.  
  - *Mobile VPN:* Enables tunnelled access bound to logical IPs, allowing continuous service across the network.  
  - *Hardware VPN:* Offers better security and load balancing for medium to large enterprises; managed centrally via web browser but costlier than software VPNs.  
  - *VPN Appliance:* Router device providing enhanced security with authorisation, authentication, and encryption.  
  - *DMVPN:* Connects multiple remote sites dynamically without routing traffic through the main VPN; useful for VoIP requiring dynamic IPsec tunnels between endpoints.  
  - *Site-to-site VPN:* Connects entire networks across locations via gateway devices; most suitable for the scenario.

- **Recommended appliance:** Cisco ASR 1002-HX SD-WAN edge router, deployed at all five sites, supports high-performance site-to-site VPN using IPsec tunnels with virtual tunnel interfaces.  
- Enables secure network-to-network, host-to-network, and host-to-host communication.  
- Supports multiple WAN connections (leased lines, SD-WAN, VPN links) in a partial mesh topology.  
- Scalable for future organisational growth.

[1] [20] [33] [34] [35] [36]

## Other Security Solutions and Measures

To enhance network security robustness, additional solutions can be implemented:

- **Adaptive Policy:**  
  Enables precise access control by permitting or denying specific resources. Policies can be managed using human-readable labels (e.g., "Finance Department" instead of IP addresses) for easier configuration consistency. [4]

- **Web Application Firewall (WAF):**  
  Example: *Cloudflare WAF* protects against application-layer threats via the cloud, shielding web applications from common attacks.  
  Works alongside Cisco FirePOWER 4145 NGIPS, which secures and monitors the network itself.  
  Deployed as a cloud service for ease of management. [15]

- **Honeypots:**  
  Deployed on company servers (e.g., in the DMZ) to divert and trap malicious traffic, preventing unauthorised access to private data and preserving confidentiality, integrity, and availability (CIA).  
  Configurable on-premises to meet organisational needs.

- **Security Information and Event Management (SIEM):**  
  Monitors network events for suspicious activity and helps mitigate data breaches.  
  Provides real-time analysis of vulnerability alerts from hosts and network devices.  
  Detects malicious actors and botnets via log analysis, enabling enterprises to manage large volumes of generated log data effectively.

## Wireless Security

The 802.11ax (Wi-Fi 6) standard is ideal for enterprises, offering improved client efficiency, higher throughput, lower latency, and better IoT battery life. Deploying Wi-Fi 6 APs ensures strong coverage across the organisation.

- **AP Choice:** Cisco Meraki MR57, providing full Wi-Fi 6 support as shown in Figure 2-1.

- **Wireless Security Configuration (applies to Staff, Guest, BYOD SSIDs unless stated):**  
  - Staff, Guest, BYOD SSIDs use **WPA2-Enterprise** with RADIUS authentication via dedicated server; APs act as authenticators.  
  - IoT SSID uses **identity PSK mode**, connecting devices by MAC address to avoid cumbersome credential input for IoT devices.

- **WPA2 Justification:**  
  - WPA3 adoption is limited and offers few substantial improvements over WPA2 for general corporate environments.  
  - WPA2-Enterprise remains a viable, widely supported, and manageable option.  
  - RADIUS traffic from APs should be accessed via VPN as it is unencrypted.

- **RADIUS CoA (Change of Authorization):**  
  - Enabled for Staff and BYOD SSIDs to allow dynamic session adjustments without re-authentication.  
  - May impact network performance but manageable within this design.

- **VLAN Tagging per SSID:**  
  - Management: VLAN 1 — 10.0.1.0/16  
  - Staff: VLAN 80 — 10.0.80.0/16  
  - Guests: VLAN 90 — 10.0.90.0/16  
  - BYOD: VLAN 100 — 10.0.100.0/16  
  - IoT: VLAN 110 — 10.0.110.0/16  

- VLANs reduce broadcast traffic, segment and restrict traffic for security.  
- Cisco Meraki MR57 supports VLAN tagging in bridge mode and mandatory DHCP from the management VLAN pool, with default gateway 10.0.1.1.  
- VLAN management complexity and misconfiguration risks require expert handling.

- **Layer 2 Isolation:**  
  - Enabled for Guest SSID to isolate guest devices from trusted network segments.  
  - Enabled for all other SSIDs to mitigate threats between devices on the wireless network.  
  - Lack of isolation risks unauthorised lateral movement within trusted SSIDs.

- **BYOD Group Policy (GP):**  
  - Can limit bandwidth (e.g., 10 Mbps per user on VLAN 100) and restrict access as needed.  
  - Dynamically assigned via RADIUS attributes to optimise network performance.  
  - Some devices may not support these controls, potentially limiting connectivity.

**Summary:**  
With growing WLAN reliance, enterprises must ensure CIA by authenticating users and using strong encryption methods to secure wireless access across all network areas.

[1] [5] [14] [16] [21] [22] [23] [24] [25] [26] [27]

## Final Thoughts
This lab highlighted the importance of deploying appropriate security appliances and designing a robust network. Using tools like Nessus, OpenVAS, and Nmap helped me identify and mitigate vulnerabilities effectively.

The three-tier LAN architecture with VLAN segmentation, Wi-Fi 6 APs, NGFWs, and SD-WAN edge routers demonstrated practical methods to secure a multi-site enterprise network. Understanding how these components work together to ensure confidentiality, integrity, and availability was invaluable.

Overall, this exercise improved my skills in implementing and managing secure network infrastructures, providing a strong foundation for my IT and cybersecurity career.

## References

[1] ‘Hybrid Campus LAN Design Guide (CVD)’. Cisco Meraki, 15 Dec. 2021, https://documentation.meraki.com/MS/Deployment_Guides/Hybrid_Campus_LAN_Design_Guide_(CVD). Accessed 18 Feb 2023.

[2] ‘IT Training | Keith Barker, The OGIT’. Keith Barker, https://www.thekeithbarker.com. Accessed 18 Feb 2023.

[3] G. Raj, “Security testing of web applications: Issues and challenges - ResearchGate,” https://www.researchgate.net/publication/263005553_Security_Testing_of_Web_Applications_Issues_and_Challenges. Accessed 18 Feb 2023.

[4] ‘Adaptive Policy Archives’. Cisco Meraki Blog, 20 Nov. 2019, https://meraki.cisco.com/blog/tag/adaptive-policy/. Accessed 18 Feb 2023.

[5] ‘Mr57’. Cisco Meraki, https://meraki.cisco.com/en-uk/product/wi-fi/indoor-access-points/mr57/. Accessed 18 Feb 2023.

[6] ‘Cisco Catalyst 9300 Series Switches Data Sheet’. Cisco, https://www.cisco.com/c/en/us/products/collateral/switches/catalyst-9300-series-switches/nb-06-cat9300-ser-data-sheet-cte-en.html. Accessed 18 Feb 2023.

[7] ‘Cisco Catalyst 9500 Series Switches Overview’. Cisco, https://www.cisco.com/site/us/en/products/networking/switches/catalyst-9500-series-switches/index.html. Accessed 18 Feb 2023.

[8] ‘Cisco ASR 1002-HX Aggregation Services Router’. Cisco, https://www.cisco.com/c/en/us/products/routers/asr-1002-hx-router/index.html. Accessed 18 Feb 2023.

[9] ‘The 5 Different Types of Firewalls Explained’. Security, https://www.techtarget.com/searchsecurity/feature/The-five-different-types-of-firewalls. Accessed 18 Feb 2023.

[10] ‘Cisco Firepower 4100 Series NGFW Appliances’. Cisco, https://www.cisco.com/c/en_uk/products/security/firepower-4100-series/index.html. Accessed 18 Feb 2023.

[11] NGFW or UTM: How to Choose | WatchGuard Technologies. 21 Dec. 2016, https://www.watchguard.com/uk/wgrd-resource-center/help-me-choose. Accessed 18 Feb 2023.

[12] ‘What Is Access Control List (ACL)? - SearchSoftwareQuality’. Networking, https://www.techtarget.com/searchnetworking/definition/access-control-list-ACL. Accessed 18 Feb 2023.

[13] ‘What Is Content Filtering and How Does It Work?’ Security, https://www.techtarget.com/searchsecurity/definition/content-filtering. Accessed 18 Feb 2023.

[14] Techtarget. Cisco launches APs, switches to enhance hybrid workplaces. https://www.techtarget.com/searchnetworking/news/252512959/Cisco-launches-APs-switches-to-enhance-hybrid-workplaces. Accessed 18 Feb 2023.

[15] Cloudflare. What is a WAF? | Web Application Firewall explained. https://www.cloudflare.com/en-gb/learning/ddos/glossary/web-application-firewall-waf/. Accessed 18 Feb 2023.

[16] ‘Change of Authorization with RADIUS (CoA) on MR Access Points’. Cisco Meraki, 5 Oct. 2020, https://documentation.meraki.com/MR/Encryption_and_Authentication/Change_of_Authorization_with_RADIUS_(CoA)_on_MR_Access_Points. Accessed 18 Feb 2023.

[17] Molenaar, Rene. ‘InterVLAN Routing’. NetworkLessons.Com, 6 Oct. 2014, https://networklessons.com/switching/intervlan-routing. Accessed 18 Feb 2023.

[18] Partial-Mesh Wide Area Network (WAN) Topology. https://www.omnisecu.com/basic-networking/site-to-site-wan-network-topologies-partial-mesh-topology.php. Accessed 18 Feb 2023.

[19] Which Cisco Switch To Buy in 2022? www.youtube.com, https://www.youtube.com/watch?v=L_t0XbBKhkg. Accessed 18 Feb 2023.

[20] Which Cisco Router To Buy in 2022? www.youtube.com, https://www.youtube.com/watch?v=ZITJW5Gwvn4. Accessed 18 Feb 2023.

[21] ‘Preparing the Enterprise for Wi-Fi 6’. Cisco, https://www.cisco.com/c/en/us/solutions/cisco-on-cisco/enterprise-wifi-6.html. Accessed 18 Feb 2023.

[22] ‘Configuring RADIUS Authentication with WPA2-Enterprise’. Cisco Meraki, 5 Oct. 2020, https://documentation.meraki.com/MR/Encryption_and_Authentication/Configuring_RADIUS_Authentication_with_WPA2-Enterprise. Accessed 18 Feb 2023.

[23] ‘IPSK with RADIUS Authentication’. Cisco Meraki, 5 Oct. 2020, https://documentation.meraki.com/MR/Encryption_and_Authentication/IPSK_with_RADIUS_Authentication. Accessed 18 Feb 2023.

[24] ‘WPA2 Enterprise vs. Personal’. Laird Connectivity, https://www.lairdconnect.com/resources/blog/wpa2-enterprise-vs-personal. Accessed 18 Feb 2023.

[25] Metzler, Sam. ‘WPA3: The Ultimate Guide’. SecureW2, 3 June 2021, https://www.securew2.com/blog/wpa3-the-ultimate-guide. Accessed 18 Feb 2023.

[26] ‘VLAN Tagging on MR Access Points’. Cisco Meraki, 5 Oct. 2020, https://documentation.meraki.com/MR/Client_Addressing_and_Bridging/VLAN_Tagging_on_MR_Access_Points. Accessed 18 Feb 2023.

[27] ‘Wireless Client Isolation’. Cisco Meraki, 5 Oct. 2020, https://documentation.meraki.com/MR/Firewall_and_Traffic_Shaping/Wireless_Client_Isolation. Accessed 18 Feb 2023.

[28] Robb, Drew. ‘Cisco Firepower NGIPS | ESecurity Planet’. ESecurityPlanet, 9 Mar. 2018, https://www.esecurityplanet.com/products/cisco-firepower-ngips/. Accessed 18 Feb 2023.

[29] Ingalls, Sam. 13 Best Intrusion Detection and Prevention Systems (IDPS) for 2023. https://www.esecurityplanet.com/products/intrusion-detection-and-prevention-systems/. Accessed 18 Feb 2023.

[30] How Do You Choose the Right IDPS Vendor and Solution for Your Specific Needs and Budget? https://www.linkedin.com/advice/0/how-do-you-choose-right-idps-vendor-solution. Accessed 18 Feb 2023.

[31] Scarfone, Karen. NIST. Guide to Intrusion Detection and Prevention Systems (IDPS)(Draft). https://csrc.nist.rip/library/alt-SP800-94r1-draft.pdf. Accessed 18 Feb 2023.

[32] Rizvi, Syed, et al. ‘Advocating for Hybrid Intrusion Detection Prevention System and Framework Improvement’. Procedia Computer Science, vol. 95, Jan. 2016, pp. 369–74. ScienceDirect, https://doi.org/10.1016/j.procs.2016.09.347. Accessed 18 Feb 2023.

[33] ‘Meraki SD-WAN’. Cisco Meraki, 5 Oct. 2020. https://documentation.meraki.com/Architectures_and_Best_Practices/Cisco_Meraki_Best_Practice_Design/Best_Practice_Design_-_MX_Security_and_SD-WAN/Meraki_SD-WAN. Accessed 18 Feb 2023.

[34] ‘VPNs: Fundamentals and Basics | TechTarget’. Networking, https://www.techtarget.com/searchnetworking/tip/VPNs-Fundamentals-and-basics. Accessed 18 Feb 2023.

[35] ‘What Is a VPN? Definition from SearchNetworking’. Networking, https://www.techtarget.com/searchnetworking/definition/virtual-private-network. Accessed 18 Feb 2023.

[36] ‘How IPsec Site-to-Site VPN Tunnels Work’. CBT Nuggets, https://www.cbtnuggets.com/blog/technology/networking/how-ipsec-site-to-site-vpn-tunnels-work. Accessed 18 Feb 2023.


