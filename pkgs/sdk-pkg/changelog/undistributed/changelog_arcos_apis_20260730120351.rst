--------------------------------------------------------------------------------
                                New
--------------------------------------------------------------------------------
* ARCOS
    * Added ACL APIs:
        * configure/unconfigure, get, verify
    * Added BFD APIs:
        * configure/unconfigure, get, verify
    * Added BGP APIs:
        * configure/unconfigure, get (incl. 6PE, L3VPN, L3VPN-SRv6), verify
    * Added Bridge Isolation APIs:
        * configure/unconfigure, get
    * Added CoPP APIs:
        * configure/unconfigure
    * Added Damping APIs:
        * configure/unconfigure
    * Added DHCP Relay APIs:
        * configure/unconfigure, get
    * Added EVPN APIs:
        * configure/unconfigure (incl. MPLS, VPWS), get (incl. MPLS, VPWS), verify
    * Added FIB APIs:
        * get, verify
    * Added FQDN Filter APIs:
        * configure/unconfigure
    * Added gNMI APIs:
        * configure/unconfigure, get
    * Added ICMP Tunneling APIs:
        * configure/unconfigure
    * Added Interface APIs:
        * configure/unconfigure, get, verify
    * Added IPFIX APIs:
        * configure/unconfigure, get
    * Added IPsec APIs:
        * configure/unconfigure, get
    * Added ISIS APIs:
        * configure/unconfigure, get, verify
    * Added Keychain APIs:
        * configure/unconfigure, get, verify
    * Added LAG APIs:
        * configure/unconfigure, get, verify
    * Added LDP APIs:
        * configure/unconfigure, get, verify
    * Added LLDP APIs:
        * configure/unconfigure, get, verify
    * Added Monitor Session APIs:
        * configure/unconfigure, get
    * Added MPLS OAM APIs:
        * exec (LSP ping, LSP traceroute)
    * Added MPLS TTL APIs:
        * configure, get
    * Added NAT APIs:
        * configure/unconfigure, get
    * Added Network Instance APIs:
        * configure/unconfigure, get, verify
    * Added OSPF APIs:
        * configure/unconfigure, get, verify
    * Added OSPFv3 APIs:
        * configure/unconfigure, get, verify
    * Added PFC APIs:
        * configure/unconfigure
    * Added Port Security APIs:
        * configure/unconfigure, get
    * Added PTP APIs:
        * configure/unconfigure
    * Added QoS APIs:
        * configure/unconfigure, get, verify
    * Added QPPB APIs:
        * configure/unconfigure
    * Added RIB APIs:
        * get, verify
    * Added Route Policy APIs:
        * configure/unconfigure, get, verify
    * Added RSVP-TE APIs:
        * configure/unconfigure, get
    * Added Segment Routing APIs:
        * configure/unconfigure, get, verify
    * Added sFlow APIs:
        * configure/unconfigure, get
    * Added SLA APIs:
        * configure/unconfigure, get
    * Added SNMP APIs:
        * configure/unconfigure, get, verify
    * Added SR-Policy APIs:
        * configure/unconfigure, get, verify
    * Added SRv6 Mobile APIs:
        * configure/unconfigure (PFCP proxy)
    * Added SRv6 OAM APIs:
        * configure/unconfigure
    * Added Static Routing APIs:
        * configure/unconfigure, get, verify
    * Added Static VXLAN APIs:
        * configure/unconfigure, get
    * Added Storm Control APIs:
        * configure/unconfigure
    * Added STP APIs:
        * configure/unconfigure, get
    * Added SyncE APIs:
        * configure/unconfigure
    * Added System APIs:
        * configure/unconfigure, exec (load config file, rollback configuration)
    * Added Traffic Engineering APIs:
        * configure/unconfigure, get, verify
    * Added Telemetry APIs:
        * configure/unconfigure, get
    * Added TWAMP APIs:
        * configure/unconfigure
    * Added Version APIs:
        * get, verify
    * Added VLAN APIs:
        * configure/unconfigure, get, verify
    * Added VRRP APIs:
        * configure/unconfigure, get, verify
    * Added unit tests for BGP, Interface, and ISIS get/verify/configure APIs

--------------------------------------------------------------------------------
                                Fix
--------------------------------------------------------------------------------
* ARCOS
    * Fixed configure_isis_traffic_engineering_router_id /
      unconfigure_isis_traffic_engineering_router_id emitting the wrong CLI
      form (`global traffic-engineering {af} router-id ...`) instead of the
      arcOS-required hyphenated token (`global traffic-engineering
      {af}-router-id ...`); IPv6 TE router-id never landed on the device
      under the old form.
    * Fixed get_isis_flex_algo_definitions reading flexible-algorithms data
      directly under the ISIS `global` key; ShowIsisConfig actually nests it
      under `config.global.flexible-algorithms`, so the lookup always
      returned empty.
    * Fixed get_isis_route calling device.parse() with a trailing prefix
      argument appended to the command string, which could not match the
      registered parser command; switched to invoking the ShowIsisRoute
      parser directly with a `prefix` parameter.
    * Fixed get_interface_status and get_isis_system_id reading
      admin_status/oper_status/system_id (underscore) instead of the
      hyphenated OpenConfig keys (admin-status/oper-status/system-id) the
      arcos parsers actually emit, so status/system-id lookups always
      returned empty; also replaced get_isis_redis_route,
      get_isis_redis_routes, and get_isis_lsp's fragile raw
      device.execute()-plus-line-splitting logic with proper parser-backed
      lookups.
    * Fixed configure_static_route/unconfigure_static_route emitting
      non-existent ArcOS CLI (`static-routes` / `route` / `next-hop`)
      instead of the actual `protocol STATIC default` / `static-route` /
      `next-hop-index` syntax.
