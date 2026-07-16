--------------------------------------------------------------------------------
                                Fix
--------------------------------------------------------------------------------
* ARCOS
    * Added missing ospf/arcos and ospfv3/arcos __init__.py (abstract token
      declaration) so the OSPF/OSPFv3 conf objects dispatch for os='arcos';
      previously build_config() raised NotImplementedError.
    * Added conf-object unit test for arcos OSPF.
