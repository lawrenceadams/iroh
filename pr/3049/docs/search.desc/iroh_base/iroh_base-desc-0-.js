searchState.loadedDescShard("iroh_base", 0, "Base types and utilities for Iroh\nSize of an encoded Ed25519 signature in bytes.\nError when decoding.\nThe encoded information had the wrong length.\nA mirror for the <code>NodeIdMappedAddr</code>, mapping a fake Ipv6 …\nA Map of <code>IpMappedAddrs</code> to <code>SocketAddr</code>\nError when decoding the public key.\nError when deserialising a <code>PublicKey</code> or a <code>SecretKey</code>.\nThe length of an ed25519 <code>PublicKey</code>, in bytes.\nThe dummy port used for all mapped addresses\nNetwork-level addressing information for an iroh node.\nThe identifier for a node in the (iroh) network.\nA public key.\nA URL identifying a relay server.\nCan occur when parsing a string into a <code>RelayUrl</code>.\nA secret key.\nEd25519 signature.\nAdd a <code>SocketAddr</code> to the map and the generated <code>IpMappedAddr</code> …\nReturn the underlying <code>SocketAddr</code>.\nGet this public key as a byte array.\nReturns the direct addresses of this peer.\nSocket addresses where the peer might be reached directly.\nConvert to a hex string limited to the first 5 bytes for a …\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the addressing info from given ticket.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nParse an Ed25519 signature from a byte slice.\nConstruct a <code>PublicKey</code> from a slice of bytes.\nCreate a secret key from its byte representation.\nParse an Ed25519 signature from its <code>R</code> and <code>s</code> components.\nCreates a new <code>NodeAddr</code> from its parts.\nParse an Ed25519 signature from a byte slice.\nGenerates a globally unique fake UDP address.\nGenerate a new <code>SecretKey</code> with a randomness generator.\nGet the <code>SocketAddr</code> for the given <code>IpMappedAddr</code>.\nGet the <code>IpMappedAddr</code> for the given <code>SocketAddr</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nReturns true, if only a <code>NodeId</code> is present.\nCreate an empty <code>IpMappedAddrs</code>\nCreates a new <code>NodeAddr</code> with no <code>relay_url</code> and no …\nThe node’s identifier.\nReturns the <code>VerifyingKey</code> for this <code>PublicKey</code>.\nThe public key of this <code>SecretKey</code>.\nBytes for the <code>R</code> component of a signature.\nReturns the relay url of this peer.\nThe node’s home relay url.\nBytes for the <code>s</code> component of a signature.\nReturns the <code>SigningKey</code> for this <code>SecretKey</code>.\nSign the given message and return a digital signature\nTickets is a serializable object combining information …\nReturn the inner byte array.\nConvert this to the bytes representing the secret part. …\nConvert this signature into a byte vector.\nVerify a signature on a message with this secret key’s …\nAdds the given direct addresses.\nAdds a relay url.\nThis looks like a ticket, but base32 decoding failed.\nAn error deserializing an iroh ticket.\nString prefix describing the kind of iroh ticket.\nFound a ticket of with the wrong prefix, indicating the …\nA token containing information for establishing a …\nThis looks like a ticket, but postcard deserialization …\nA ticket is a serializable object combining information …\nVerification of the deserialized bytes failed.\nDeserialize from a string.\nCreates a ticket from given addressing info.\nReturns the argument unchanged.\nReturns the argument unchanged.\nDeserialize from the base32 string representation bytes.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCreates a new ticket.\nThe <code>NodeAddr</code> of the provider for this ticket.\nSerialize to string.\nSerialize to bytes used in the base32 string …\nThe expected prefix.")