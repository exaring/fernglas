# VRF/Routing-Instances

VRFs/Routing-Instances are supported out of the box and do not need any
configuration for BMP- and MPBGP-Sessions.

## BGP Session in VRF

If the BGP Session (on the router) belongs to a routing-instance fernglas should
be configured to belong to the same RI:

```
# config.yml
collectors:
    bgp_peer:
        bind: "192.0.2.1:179"
        default_peer_config:
            asn: 64496
            router_id: 192.0.2.1
            # same RD as peer
            route_distinguisher: 192.1.2.5:100
```

If this configuration is missing routes would be added as if they were in the
default routing-instance instead of the routing-instance (and consequently matched when
querying for routes of the default routing-instance.)
