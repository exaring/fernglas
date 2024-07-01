use zettabgp::afi::BgpRD;

use serde::de::{self, Visitor};
use serde::{Serialize, Serializer};
use std::fmt::{self, Display};
use std::net::Ipv4Addr;
use std::str::FromStr;

#[derive(Default, Copy, Clone, Hash, Eq, PartialEq, Debug)]
pub enum RouteDistinguisher {
    #[default]
    Default,
    Type0 {
        asn: u16,
        value: u32,
    },
    Type1 {
        ip: Ipv4Addr,
        value: u16,
    },
    Type2 {
        asn: u32,
        value: u16,
    },
}

impl RouteDistinguisher {
    pub fn is_default(&self) -> bool {
        *self == RouteDistinguisher::Default
    }
}

static EXPECT_MESSAGE: &str = r#"expecting a route distinguisher in one of the following formats:
Type0: "{2-byte ASN}:{4-byte value}" | u16:u32  (example: 2222:1000000)
Type1: "{4-byte IP}:{2-byte value}"  | ipv4:u16 (example: "1.2.3.4:555")
Type2: "{4-byte ASN}:{2-byte value}" | u32:u16  (example: "1000000:3232")"#;

impl Serialize for RouteDistinguisher {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> de::Deserialize<'de> for RouteDistinguisher {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct RdVisitor;

        impl<'de> Visitor<'de> for RdVisitor {
            type Value = RouteDistinguisher;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str(EXPECT_MESSAGE)
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                value
                    .parse::<RouteDistinguisher>()
                    .map_err(|emsg| de::Error::invalid_value(de::Unexpected::Str(value), &emsg))
            }
        }

        deserializer.deserialize_str(RdVisitor)
    }
}

impl Display for RouteDistinguisher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RouteDistinguisher::Default => write!(f, "0:0"),
            RouteDistinguisher::Type0 { asn, value } => write!(f, "{asn}:{value}"),
            RouteDistinguisher::Type1 { ip, value } => write!(f, "{ip}:{value}"),
            RouteDistinguisher::Type2 { asn, value } => write!(f, "{asn}:{value}"),
        }
    }
}

impl FromStr for RouteDistinguisher {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "0:0" {
            return Ok(RouteDistinguisher::Default);
        }
        let (k, v) = s.split_once(':').ok_or(EXPECT_MESSAGE)?;

        let v = v.parse::<u32>().map_err(|_| EXPECT_MESSAGE)?;

        if let Ok(asn) = k.parse::<u32>() {
            return if asn > u16::MAX.into() && v <= u16::MAX.into() {
                Ok(RouteDistinguisher::Type2 {
                    asn,
                    value: v as u16,
                })
            } else if asn <= u16::MAX.into() {
                Ok(RouteDistinguisher::Type0 {
                    asn: asn as u16,
                    value: v,
                })
            } else {
                Err(EXPECT_MESSAGE)
            };
        }

        if let Ok(ip) = k.parse::<Ipv4Addr>() {
            if v <= u16::MAX.into() {
                return Ok(RouteDistinguisher::Type1 {
                    ip,
                    value: v as u16,
                });
            }
        }

        Err(EXPECT_MESSAGE)
    }
}

impl TryFrom<BgpRD> for RouteDistinguisher {
    type Error = u16;

    fn try_from(rd: BgpRD) -> Result<Self, Self::Error> {
        let (high, low) = (rd.rdh, rd.rdl);
        // everything zero => default routing instance
        if high == 0 && low == 0 {
            return Ok(RouteDistinguisher::Default);
        }
        let high = high.to_be_bytes();
        let low = low.to_be_bytes();
        // RD-Type is encoded in the 2 highest bytes (network endian)
        Ok(match u16::from_be_bytes([high[0], high[1]]) {
            0 => RouteDistinguisher::Type0 {
                asn: u16::from_be_bytes([high[2], high[3]]),
                value: rd.rdl,
            },
            1 => RouteDistinguisher::Type1 {
                ip: Ipv4Addr::from([high[2], high[3], low[0], low[1]]),
                value: u16::from_be_bytes([low[2], low[3]]),
            },
            2 => RouteDistinguisher::Type2 {
                asn: u32::from_be_bytes([high[2], high[3], low[0], low[1]]),
                value: u16::from_be_bytes([low[2], low[3]]),
            },
            e => return Err(e),
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn decode_route_distingisher_from_string() {
        let default = "0:0".parse();
        let rd_type0 = "1234:5678".parse();
        let rd_type1 = "10.0.0.1:5678".parse();
        let rd_type2 = "70000:1234".parse();
        assert_eq!(default, Ok(RouteDistinguisher::Default));
        assert_eq!(
            rd_type0,
            Ok(RouteDistinguisher::Type0 {
                asn: 1234,
                value: 5678
            })
        );
        assert_eq!(
            rd_type1,
            Ok(RouteDistinguisher::Type1 {
                ip: Ipv4Addr::from([10, 0, 0, 1]),
                value: 5678
            })
        );
        assert_eq!(
            rd_type2,
            Ok(RouteDistinguisher::Type2 {
                asn: 70000,
                value: 1234
            })
        );

        assert!("70000:70000".parse::<RouteDistinguisher>().is_err());
        assert!("10.0.0.1:70000".parse::<RouteDistinguisher>().is_err());
    }

    #[test]
    fn encode_route_distingisher() {
        assert_eq!(
            "1234:5678",
            &RouteDistinguisher::Type0 {
                asn: 1234,
                value: 5678
            }
            .to_string()
        );
        assert_eq!(
            "192.1.2.3:5678",
            &RouteDistinguisher::Type1 {
                ip: Ipv4Addr::from([192, 1, 2, 3]),
                value: 5678
            }
            .to_string()
        );
        assert_eq!(
            "70000:1234",
            &RouteDistinguisher::Type2 {
                asn: 70000,
                value: 1234
            }
            .to_string()
        );
    }

    #[test]
    fn decode_route_distingisher_from_zettabgp_rd() {
        let default = BgpRD {
            rdh: u32::from_be_bytes([0, 0, 0, 0]),
            rdl: u32::from_be_bytes([0, 0, 0, 0]),
        }
        .try_into();
        assert_eq!(default, Ok(RouteDistinguisher::Default));

        let rd_type0 = BgpRD {
            rdh: u32::from_be_bytes([0, 0, 0x12, 0x34]),
            rdl: u32::from_be_bytes([0, 0, 0x56, 0x78]),
        }
        .try_into();
        assert_eq!(
            rd_type0,
            Ok(RouteDistinguisher::Type0 {
                asn: 0x1234,
                value: 0x5678
            })
        );

        let rd_type1 = BgpRD {
            rdh: u32::from_be_bytes([0, 1, 10, 0]),
            rdl: u32::from_be_bytes([0, 255, 0x56, 0x78]),
        }
        .try_into();
        assert_eq!(
            rd_type1,
            Ok(RouteDistinguisher::Type1 {
                ip: Ipv4Addr::from([10, 0, 0, 255]),
                value: 0x5678
            })
        );

        let rd_type2 = BgpRD {
            rdh: u32::from_be_bytes([0, 2, 0x43, 0x21]),
            rdl: u32::from_be_bytes([0x98, 0x76, 0x54, 0x32]),
        }
        .try_into();
        assert_eq!(
            rd_type2,
            Ok(RouteDistinguisher::Type2 {
                asn: 0x43219876,
                value: 0x5432
            })
        );
    }
}
