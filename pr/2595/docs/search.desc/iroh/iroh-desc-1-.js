searchState.loadedDescShard("iroh", 1, "Metrics tracked for the relay server\nA plain non-Tls <code>tokio::net::TcpStream</code>\nConfiguration for the Relay HTTP and HTTPS server.\nA running Relay + STUN server.\nThe task for a running server actor.\nConfiguration for the full Relay &amp; STUN server.\nConfiguration for the STUN server.\nA Tls wrapped <code>tokio::net::TcpStream</code>\nTLS configuration for Relay server.\nAborts the server.\nAdds a new connection to the server and serves it.\nBurst limit for accepting new connection. Unlimited if not …\nRate limit for accepting new connection. Unlimited if not …\nNumber of connections we have accepted\nThe socket address on which the STUN server should bind.\nBytes received from a <code>FrameType::SendPacket</code>\nBytes sent from a <code>FrameType::SendPacket</code>\nMode for getting a cert.\nCreate a <code>ClientConnHandler</code>, which can verify connections …\nCloses the server and waits for the connections to …\nNumber of accepted ‘iroh derp http’ connection upgrades\n<code>FrameType::SendPacket</code> dropped that are disco messages\n<code>FrameType::SendPacket</code> received that are disco messages\n<code>FrameType::SendPacket</code> sent that are disco messages\nNumber of connections we have removed because of an error\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nNumber of <code>FrameType::Ping</code>s received\nThe socket address the HTTP server is listening on.\nThe socket address on which the Relay HTTP server should …\nThe socket address the HTTPS server is listening on.\nThe socket address on which to serve the HTTPS server.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nWhether or not the relay <code>ServerActorTask</code> is closed.\nRate limits.\nReturns the server metadata cert that can be sent by the …\nSocket to serve metrics on.\nTODO: replace with builder\nPackets of other <code>FrameType</code>s dropped\nPackets of other <code>FrameType</code>s received\nPackets of other <code>FrameType</code>s sent\nReturns the server’s public key.\nConfiguration for the Relay server, disabled if <code>None</code>.\nReturns the server’s secret key.\nThe iroh secret key of the Relay server.\n<code>FrameType::SendPacket</code> dropped, that are not disco messages\n<code>FrameType::SendPacket</code> received, that are not disco messages\n<code>FrameType::SendPacket</code> sent, that are not disco messages\nNumber of <code>FrameType::Pong</code>s sent\nRequests graceful shutdown.\nStarts the server.\nConfiguration for the STUN server, disabled if <code>None</code>.\nThe socket address the STUN server is listening on.\nReturns the handle for the task.\nTLS configuration for the HTTPS server.\nNumber of unique client keys per day\nNumber of <code>FrameType::Unknown</code> received\nNumber of accepted websocket connections\nThe TLS certificate chain.\nConfiguration for Let’s Encrypt certificates.\nThe TLS private key.\nThe <code>AlternateServer</code>atribute\nErrors that can occur when handling a STUN packet.\nThe <code>ErrorCode</code>atribute\nerror response\nThe <code>Fingerprint</code>atribute\nindication\nSTUN request had bogus fingerprint.\nThe STUN message could not be parsed or is otherwise …\nSTUN response has malformed attributes.\nThe <code>MappedAddress</code>atribute\nThe STUN message class. Although there are four message …\nClass used to decode STUN messages\nThe <code>MessageIntegrity</code>atribute\nThe <code>MessageIntegritySha256</code>atribute\nSTUN request didn’t end in fingerprint.\nThe <code>Nonce</code>atribute\nSTUN request is not a binding request when it should be.\nSTUN packet is not a response when it should be.\nThe <code>PasswordAlgorithm</code>atribute\nThe <code>PasswordAlgorithms</code>atribute\nThe <code>Realm</code>atribute\nrequest\nThe <code>Software</code>atribute\nSTUN Attributes that can be attached to a <code>StunMessage</code>\nDescribes an error decoding a <code>StunMessage</code>\nsuccess response\nThe transaction ID is a 96-bit identifier, used to …\nThe <code>Unknown</code>atribute\nThe <code>UnknownAttributes</code>atribute\nThe <code>UserHash</code>atribute\nThe <code>UserName</code>atribute\nThe <code>XorMappedAddress</code>atribute\nReturns a reference to the internal attribute value or an …\nReturns a reference to the bytes that represents the …\nReturns a reference to the internal attribute value or an …\nReturns a reference to the internal attribute value or an …\nReturns a reference to the internal attribute value or an …\nReturns a reference to the internal attribute value or an …\nReturns a reference to the internal attribute value or an …\nReturns a reference to the internal attribute value or an …\nReturns a reference to the internal attribute value or an …\nReturns a reference to the internal attribute value or an …\nReturns a reference to the internal attribute value or an …\nReturns a reference to the internal attribute value or an …\nReturns a reference to the internal attribute value or an …\nReturns a reference to the internal attribute value or an …\nReturns a reference to the internal attribute value or an …\nReturns a reference to the internal attribute value or an …\nReturns a reference to the internal attribute value or an …\nReturns the STUN attribute type of this instance.\nDecodes the STUN raw buffer\nCreates a cryptographically random transaction ID chosen …\nReturns a reference to the <code>AlternateServer</code> attribute.\nReturns a reference to the <code>ErrorCode</code> attribute.\nReturns a reference to the <code>Fingerprint</code> attribute.\nReturns a reference to the <code>MappedAddress</code> attribute.\nReturns a reference to the <code>MessageIntegrity</code> attribute.\nReturns a reference to the <code>MessageIntegritySha256</code> …\nReturns a reference to the <code>Nonce</code> attribute.\nReturns a reference to the <code>PasswordAlgorithm</code> attribute.\nReturns a reference to the <code>PasswordAlgorithms</code> attribute.\nReturns a reference to the <code>Realm</code> attribute.\nReturns a reference to the <code>Software</code> attribute.\nReturns a reference to the <code>Unknown</code> attribute.\nReturns a reference to the <code>UnknownAttributes</code> attribute.\nReturns a reference to the <code>UserHash</code> attribute.\nReturns a reference to the <code>UserName</code> attribute.\nReturns a reference to the <code>XorMappedAddress</code> attribute.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nGets the context associated to this decoder\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nReports whether b is a STUN message.\nReturns true if this <code>StunAttribute</code> is <code>AlternateServer</code>\nReturns true if this <code>StunAttribute</code> is <code>ErrorCode</code>\nReturns true if this <code>StunAttribute</code> is <code>Fingerprint</code>\nReturns true if this <code>StunAttribute</code> is <code>MappedAddress</code>\nReturns true if this <code>StunAttribute</code> is <code>MessageIntegrity</code>\nReturns true if this <code>StunAttribute</code> is …\nReturns true if this <code>StunAttribute</code> is <code>Nonce</code>\nReturns true if this <code>StunAttribute</code> is <code>PasswordAlgorithm</code>\nReturns true if this <code>StunAttribute</code> is <code>PasswordAlgorithms</code>\nReturns true if this <code>StunAttribute</code> is <code>Realm</code>\nReturns true if this <code>StunAttribute</code> is <code>Software</code>\nReturns true if this <code>StunAttribute</code> is <code>Unknown</code>\nReturns true if this <code>StunAttribute</code> is <code>UnknownAttributes</code>\nReturns true if this <code>StunAttribute</code> is <code>UserHash</code>\nReturns true if this <code>StunAttribute</code> is <code>UserName</code>\nReturns true if this <code>StunAttribute</code> is <code>XorMappedAddress</code>\nSTUN Methods Registry\nParses a STUN binding request.\nParses a successful binding response STUN packet. The IP …\nGenerates a binding request STUN packet.\nGenerates a binding response.\nBinding\nReserved\nShared secret\nA drop guard to clean up test infrastructure.\nHandle and drop guard for test DNS and Pkarr servers.\nCreate a DNS resolver with a single nameserver.\nCreate a <code>ConcurrentDiscovery</code> with <code>DnsDiscovery</code> and …\nCreate a <code>DnsResolver</code> configured to use the test DNS server.\nReturns the argument unchanged.\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nThe socket address of the DNS server.\nThe node origin domain.\nWait until a Pkarr announce for a node is published to the …\nThe HTTP URL of the Pkarr server.\nRun DNS and Pkarr servers on localhost.\nRuns a relay server with STUN enabled suitable for tests.\nRun DNS and Pkarr servers on localhost with the specified …\nA token containing everything to get a file from the …\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nCreates a new ticket.\nThe <code>NodeAddr</code> of the provider for this ticket.\nError generating the certificate.\nError creating QUIC config.\nError for generating iroh p2p TLS configs.\nX.509 certificate handling.\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nCreate a TLS client configuration.\nCreate a TLS server configuration.\nAn error that occurs during certificate generation.\nAn X.509 certificate with a libp2p-specific extension is …\nThe contents of the specific libp2p extension, containing …\nAn error that occurs during certificate parsing.\nAn error that occurs during signature verification.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nGenerates a self-signed TLS certificate that includes a …\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nAttempts to parse the provided bytes as a <code>P2pCertificate</code>.\nThe <code>PublicKey</code> of the remote peer.\nVerify the <code>signature</code> of the <code>message</code> signed by the secret …\nA join handle that owns the task it is running, and aborts …\nHolds a handle to a task and aborts it on drop.\nResolves to pending if the inner is <code>None</code>.\nA join handle that owns the task it is running, and aborts …\nIO utility to chain <code>AsyncRead</code>s together.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nFuture to be polled.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCreate a <code>CancelOnDrop</code> with a name and a handle to a task.\nStream for the <code>chain</code> method.\nChain two <code>AsyncRead</code>s together.\nReturns the argument unchanged.\nGets mutable references to the underlying readers in this …\nGets pinned mutable references to the underlying readers …\nGets references to the underlying readers in this <code>Chain</code>.\nCalls <code>U::from(self)</code>.\nConsumes the <code>Chain</code>, returning the wrapped readers.\nBuilder for the <code>Node</code>.\nUse a custom discovery mechanism.\nThe default bind addr of the RPC .\nUse the default discovery mechanism.\nDisable docs completely.\nGarbage collection is disabled.\nConfiguration for node discovery.\nStorage backend for documents.\nPersistent node.\nPolicy for garbage collection.\nGarbage collection is run at the given interval.\nThe quic-rpc server endpoint for the iroh node.\nIn memory\nIn memory node.\nIn-memory storage.\nA server which implements the iroh node.\nUse no node discovery mechanism.\nFile-based persistent storage.\nOn disk persistet, at this location.\nA node that is initialized but not yet spawned.\nHandler for incoming connections.\nThe current status of the RPC endpoint.\nRunning on this port.\nStopped.\nConfiguration for storage.\nHandle an incoming connection.\nRegisters a protocol handler for incoming connections.\nBinds the node service to a different socket.\nReturns the <code>crate::blobs::store::Store</code> used by the node.\nBuilds a node without spawning it.\nReturns a token that can be used to cancel the node.\nCleans up an existing rpc lock\nReturns a client to control this node over an in-memory …\nReturn a client to control this node over an in-memory …\nDisables documents support on this node completely.\nOptionally set a custom DNS resolver to use for the magic …\nReturns a reference to the <code>Downloader</code> used by the node.\nConfigure the default iroh rpc endpoint, on the default …\nConfigure the default iroh rpc endpoint.\nReturns the <code>Endpoint</code> of the node.\nReturns the <code>Endpoint</code> of the node.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nSets the garbage collection policy.\nReturns a protocol handler for an ALPN.\nReturns a protocol handler for an ALPN.\nReturns a reference to the <code>Gossip</code> handle used by the node.\nGet the relay server we are connected to.\nSkip verification of SSL certificates from relay servers\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nWhether to log the SSL pre-master key.\nLoad the current RPC status from the given location.\nThe address on which the node socket is bound.\nConvenience method to get just the addr part of …\nLists the local endpoint of this node.\nReturns a reference to the used <code>LocalPoolHandle</code>.\nReturns a reference to the used <code>LocalPoolHandle</code>.\nReturns a new builder for the <code>Node</code>, by default configured …\nReturns a new builder for the <code>Node</code>, by default configured …\nReturns <code>Some(addr)</code> if an RPC endpoint is running, <code>None</code> …\nSets the node discovery mechanism.\nReturns the <code>PublicKey</code> of the node.\nPersist all node data in the provided directory.\nReturns a new builder for the <code>Node</code>, configured to persist …\nReturns a new builder for the <code>Node</code>, configured to persist …\nRegister a callback for when GC is done.\nSets the relay servers to assist in establishing …\nConfigure rpc endpoint.\nUses the given <code>SecretKey</code> for the <code>PublicKey</code> instead of a …\nCalled when the node shuts down.\nCalled when the node shuts down.\nShutdown the node.\nSpawns the <code>Node</code> in a tokio task.\nSpawns the node and starts accepting connections.\nStore the current rpc status.\nCreates a new builder for <code>Node</code> using the given databases.\nActual connected RPC client.\nThe port we are connected on.\nUtilities for filesystem operations.\nUtilities for working with tokio io\nConfiguration paths for iroh.\nGeneric utilities to track progress of data transfers.\nA data source\nInformation about the content on a path\nThis function converts an already canonicalized path to a …\ntotal number of files in the directory\nReturns the argument unchanged.\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nHelper function that translates a key that was derived …\nLoads a <code>SecretKey</code> from the provided file, or stores a …\nReturns blob name for this data source.\nCreates a new <code>DataSource</code> from a <code>PathBuf</code>.\nReturns the path of this data source.\nWalks the directory to get the total size and number of …\nHelper function that creates a document key from a …\nThis function converts a canonicalized relative path to a …\nCreate data sources from a directory.\nCreate data sources from a path.\ntotal size of all the files in the directory\nCreates a new <code>DataSource</code> from a <code>PathBuf</code> and a custom name.\nTodo: gather more information about validation errors. …\nThe data failed to validate\nGeneric io error. We were unable to read the data.\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nPath to the node’s file based blob store.\nPath to the console state\nPath to the <code>iroh_docs::AuthorId</code> of the node’s default …\nPath to the iroh-docs document database\nPaths to files or directories used by Iroh.\nPath to store known peer data.\nPath to RPC lock file, containing the RPC port if running.\nPath to the node’s secret key for the …\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nGet the path for this <code>IrohPaths</code> by joining the name to a …\nA sender for progress messages.\nA wrapper around <code>AsyncRead</code> which increments a …\nA generic progress event emitter.\nA writer that tries to send the total number of bytes …\nBlock until the message is sent.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nIncrements the progress by <em>amount</em>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nReturn the inner writer\nCreates a new emitter.\nCreate a new <code>ProgressWriter</code> from an inner writer\nCreate a new progress sender.\nCreate a no-op progress sender.\nSend a message\nSets a new total in case you did not now the total up …\nReturns a receiver that gets incremental values.\nTry to send a message.\nWraps an <code>AsyncRead</code> which implicitly calls …")