use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

/// The dummy port used for all mapped addresses
pub const MAPPED_ADDR_PORT: u16 = 12345;

/// Can occur when converting a [`SocketAddr`] to an [`IpMappedAddr`]
#[derive(Debug, thiserror::Error)]
#[error("Failed to convert: {0}")]
pub struct IpMappedAddrError(String);

/// A mirror for the `NodeIdMappedAddr`, mapping a fake Ipv6 address with an actual IP address.
///
/// You can consider this as nothing more than a lookup key for an IP the [`MagicSock`] knows
/// about.
///
/// And in our QUIC-facing socket APIs like [`AsyncUdpSocket`] it
/// comes in as the inner [`SocketAddr`], in those interfaces we have to be careful to do
/// the conversion to this type.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct IpMappedAddr(pub(crate) SocketAddr);

/// Counter to always generate unique addresses for [`NodeIdMappedAddr`].
static IP_ADDR_COUNTER: AtomicU64 = AtomicU64::new(1);

impl IpMappedAddr {
    /// The Prefix/L of our Unique Local Addresses.
    const ADDR_PREFIXL: u8 = 0xfd;
    /// The Global ID used in our Unique Local Addresses.
    const ADDR_GLOBAL_ID: [u8; 5] = [21, 7, 10, 81, 11];
    /// The Subnet ID used in our Unique Local Addresses.
    const ADDR_SUBNET: [u8; 2] = [0, 1];

    /// Generates a globally unique fake UDP address.
    ///
    /// This generates and IPv6 Unique Local Address according to RFC 4193.
    pub fn generate() -> Self {
        let mut addr = [0u8; 16];
        addr[0] = Self::ADDR_PREFIXL;
        addr[1..6].copy_from_slice(&Self::ADDR_GLOBAL_ID);
        addr[6..8].copy_from_slice(&Self::ADDR_SUBNET);

        let counter = IP_ADDR_COUNTER.fetch_add(1, Ordering::Relaxed);
        addr[8..16].copy_from_slice(&counter.to_be_bytes());

        Self(SocketAddr::new(
            IpAddr::V6(Ipv6Addr::from(addr)),
            MAPPED_ADDR_PORT,
        ))
    }

    /// Return the underlying [`SocketAddr`].
    pub fn addr(&self) -> SocketAddr {
        self.0
    }
}

impl TryFrom<SocketAddr> for IpMappedAddr {
    type Error = IpMappedAddrError;

    fn try_from(value: SocketAddr) -> std::result::Result<Self, Self::Error> {
        match value {
            SocketAddr::V4(_) => Err(IpMappedAddrError(String::from(
                "IpMappedAddrs are all Ipv6, found Ipv4 address",
            ))),
            SocketAddr::V6(addr) => {
                if addr.port() != MAPPED_ADDR_PORT {
                    return Err(IpMappedAddrError(String::from("not mapped addr")));
                }
                let octets = addr.ip().octets();
                if octets[6..8] != IpMappedAddr::ADDR_SUBNET {
                    return Err(IpMappedAddrError(String::from("not an IpMappedAddr")));
                }
                Ok(IpMappedAddr(value))
            }
        }
    }
}

impl std::fmt::Display for IpMappedAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "IpMappedAddr({})", self.0)
    }
}

#[derive(Debug, Clone)]
/// A Map of [`IpMappedAddrs`] to [`SocketAddrs`]
pub struct IpMappedAddrs(Arc<std::sync::Mutex<BTreeMap<IpMappedAddr, SocketAddr>>>);

impl IpMappedAddrs {
    /// Create an empty [`IpMappedAddrs`]
    pub fn new() -> Self {
        Self(Arc::new(std::sync::Mutex::new(BTreeMap::new())))
    }

    /// Add a [`SocketAddr`] to the map and the generated [`IpMappedAddr`] it is now associated with back.
    ///
    /// If this [`SocketAddr`] already exists in the map, it returns its associated [`IpMappedAddr`].
    pub fn add(&self, ip_addr: SocketAddr) -> IpMappedAddr {
        let mut map = self.0.lock().expect("poisoned");
        for (mapped_addr, ip) in map.iter() {
            if ip == &ip_addr {
                return *mapped_addr;
            }
        }
        let ip_mapped_addr = IpMappedAddr::generate();
        map.insert(ip_mapped_addr, ip_addr);
        ip_mapped_addr
    }

    /// Get the [`IpMappedAddr`] for the given [`SocketAddr`].
    pub fn get_mapped_addr(&self, ip_addr: &SocketAddr) -> Option<IpMappedAddr> {
        let map = self.0.lock().expect("poisoned");
        for (mapped_addr, ip) in map.iter() {
            if ip == ip_addr {
                return Some(*mapped_addr);
            }
        }
        None
    }

    /// Get the [`SocketAddr`] for the given [`IpMappedAddr`].
    pub fn get_ip_addr(&self, mapped_addr: &IpMappedAddr) -> Option<SocketAddr> {
        let map = self.0.lock().expect("poisoned");
        map.get(mapped_addr).copied()
    }
}

impl Default for IpMappedAddrs {
    fn default() -> Self {
        IpMappedAddrs::new()
    }
}
