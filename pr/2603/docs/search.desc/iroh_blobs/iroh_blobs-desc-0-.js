searchState.loadedDescShard("iroh_blobs", 0, "Blobs layer for iroh.\nA format identifier\nThe hash for the empty byte range (<code>b&quot;&quot;</code>).\nHash type used throughout.\nA hash and format pair\nA sequence of BLAKE3 hashes\nBlock size used by iroh, 2^4*1024 = 16KiB\nRaw blob\nBytes of the hash.\nHandle downloading blobs and collections concurrently and …\nFunctions to export data from a store\nConvert to a base32 string limited to the first 10 bytes …\nDefines data formats for HashSeq.\nThe format\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nCreate a <code>Hash</code> from its raw bytes representation.\nThe client side API\nThe hash\nCreate a new hash and format pair, using the collection …\ntraits related to collections of blobs\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nIs hash seq format\nIs raw format\nMetrics for iroh-blobs\nCalculate the hash of the provided bytes.\nCreate a new hash and format pair.\nProtocol for transferring content-addressed blobs and …\nThe server side API\nCreate a new hash and format pair, using the default (raw) …\nImplementations of blob stores\nConvert the hash to a hex string.\nUtility functions and types.\nAn error occurred that prevents the request from being …\nFailed to receive response from service.\nThe request was cancelled by us.\nThe download was cancelled by us\nThe request is already complete in the local store.\nConcurrency limits for the <code>Downloader</code>.\nType of connections returned by the Dialer.\nType of connections the Getter requires to perform a …\nTrait modeling a dialer. This allows for IO-less testing.\nError returned when a download could not be completed.\nFailed to download from any provider\nHandle to interact with a download request.\nThe kind of resource to download.\nA download request.\nHandle for the download services.\nAn error occurred that suggests the node should not be …\nSignals what should be done with the request when it fails.\nOutput returned from <code>Getter::get</code>.\nTrait modelling performing a single request over a …\nIdentifier for a download intent.\nTrait modelling the intermediary state when a connection …\nThe request needs a connection to continue.\nType of the intermediary state returned from <code>Self::get</code> if …\nNo provider nodes found\nConfiguration for retry behavior of the <code>Downloader</code>.\nAn error occurred in which neither the node nor the …\nCancel a download.\nGet the format of this download\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns a future that checks the local store if the …\nGet the hash of this download\nGet the <code>HashAndFormat</code> pair of this download\nThe initial delay to wait before retrying a node. On …\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCheck if a node is being dialed.\nMaximum number of nodes to dial concurrently for a single …\nMaximum number of requests the service performs …\nMaximum number of requests performed by a single node …\nMaximum number of open connections the service maintains.\nMaximum number of retry attempts for a node that failed to …\nCreate a new download request.\nCreate a new Downloader with the default <code>ConcurrencyLimits</code> …\nGet the node id of our node.\nDeclare that certains nodes can be used to download a hash.\nGet the number of dialing nodes.\nProceeds the download with the given connection.\nPass a progress sender to receive progress updates.\nQueue a download.\nDial a node.\nCreate a new Downloader with custom <code>ConcurrencyLimits</code> and …\nWe got an error and need to abort.\nWe are done with the whole operation.\nWe finished exporting a blob\nProgress events for an export operation\nThe download part is done for this id, we are now …\nWe have made progress exporting the data.\nExport a hash to the local file system.\nExport a single blob to a file on the local filesystem.\nExport all entries of a collection, recursively, to files …\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nThe hash of the entry.\nUnique id of the entry.\nUnique id of the entry that is being exported.\nUnique id of the entry that is being exported.\nOperation-specific metadata.\nThe offset of the progress, in bytes.\nThe path to the file where the data is exported.\nThe size of the entry in bytes.\nThe collection type used by iroh\nA collection of blobs\nThe header for the collection format.\nA simple store trait for loading blobs\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nCheck if this collection is empty\nIterate over the blobs in this collection\nGet the number of blobs in this collection\nLoad a blob from the store\nCreate a new collection from a hash sequence and metadata.\nLoad a collection from a store given a root hash\nAdd the given blob to the collection.\nRead the collection from a get fsm.\nRead the collection and all it’s children from a get fsm.\nStore a collection in a store. returns the root hash of …\nConvert the collection to an iterator of blobs, with the …\nError when opening a stream\nError when decoding, e.g. hash mismatch\nA generic error\nError when processing a response\nError when reading from the stream\nStats about the transfer.\nError when writing the handshake or request to the stream\nThe number of bytes read\nThe number of bytes written\nFunctions that use the iroh-blobs protocol in conjunction …\nThe time it took to transfer the data\nError returned from get operations\nReturns the argument unchanged.\nReturns the argument unchanged.\nFinite state machine for get responses.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nTransfer rate in megabits per second\nTypes for get progress state management.\nUtilities for complex get requests.\nWe got an error and need to abort.\nAll operations finished.\nThe id of a blob in a transfer\nInformation about a the status of a blob in a store.\nA child blob (child id &gt; 0)\nThe requested data is completely available in the local …\nwe have the blob completely\nA new connection was established.\nWe are done with <code>id</code>, and the hash is <code>hash</code>.\nProgress updates for the get operation.\nAn item was found with hash <code>hash</code>, from now on referred to …\nAn item was found with hash <code>hash</code>, from now on referred to …\nData was found locally.\nOutput of <code>get_to_db_in_steps</code>.\nIntermediary state returned from <code>get_to_db_in_steps</code> for a …\nInitial state if subscribing to a running or queued …\nwe don’t have the blob at all\nThe requested data is not fully available in the local …\nwe have the blob partially\nWe got progress ingesting item <code>id</code>.\nThe root blob (child id 0)\nGet information about a blob in a store.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nGet a blob or collection into a store.\nGet a blob or collection into a store, yielding if a …\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nRanges that are missing locally and need to be requested.\nProceed with the download by providing a connection to a …\nThe size of the blob, if known.\nGiven a partial entry, get the valid ranges.\nRanges that are valid locally.\nThe partial entry.\nThe size of the entry in bytes.\nThe ranges that are available locally.\nchild offset\nIdentifier for this blob within this download.\nNumber of children in the collection, if known.\nThe hash of the entry.\nThe hash of the entry.\nThe name of the entry.\nA new unique progress id for this entry.\nThe unique id of the entry.\nThe unique id of the entry.\nThe offset of the progress, in bytes.\nThe size of the entry in bytes.\nThe size of the entry in bytes.\nThe ranges that are available locally.\nOur download request is invalid.\nFailures for a get operation\nNetwork or IO operation failed.\nOperation failed on the local node.\nRemote behaved in a non-compliant way.\nHash not found.\nRemote has reset the connection.\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nState while we are reading content\nState before reading a size header\nError that you can get from <code>AtBlobHeader::next</code>\nState when finishing the get response\nState of the get response machine after the handshake has …\nState after we have read all the content for a blob\nInitial state of the get response machine\nState of the get response when we start reading a child\nState of the get response when we start reading a …\nThe next state after reading a content item\nQuic connection is closed.\nRequest is empty\nNo more children expected\nPossible next states after the handshake has been sent\nError that you can get from <code>AtConnected::next</code>\nDecode error that you can get once you have sent the …\nWe are done with this blob\nThe next state after the end of a blob\nA generic io error\nGeneric io error\nA generic io error\nThe hash of a leaf did not match the expected hash\nA parent was not found or invalid, so the provider stopped …\nWe expect more content\nResponse is expected to have more children\nEof when reading the size header\nA chunk was not found or invalid, so the provider stopped …\nThe hash of a parent did not match the expected hash\nA parent was not found or invalid, so the provider stopped …\nError when serializing the request\nQuinn read error when reading the size header\nError when reading from the stream\nThe serialized request is too long to be sent\nFirst response is a child\nFirst response is either a collection or a single blob\nError when writing the request to the <code>SendStream</code>.\nThe offset of the child we are currently reading\nConcatenate the entire response into a vec\nConcatenate the entire response into a vec\nDrain the response and throw away the result\nDrain the response and throw away the result\nFinish the get response without reading further\nFinish the get response without reading further\nImmediately finish the get response without reading further\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nHash of the root blob\nThe hash of the blob we are reading.\nThe hash of the blob we are reading.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCreate a new get response\nInitiate a new bidi stream to use for the get response\nSend the request and move to the next state\nGo into the next state, reading the header\nGo into the next state, reading the header\nRead the size header, returning it and going into the …\nRead the next item, either content, an error, or the end …\nRead the next child, or finish\nFinish the get response, returning statistics\nThe current offset of the blob we are reading.\nThe current offset of the blob we are reading.\nThe ranges we have requested for the child\nThe ranges we have requested for the child\nThe ranges we have requested for the current hash.\nThe entry point of the get response machine\nThe geometry of the tree we are currently reading.\nWrite the entire blob to a slice writer.\nWrite the entire blob to a slice writer.\nWrite the entire stream for this blob to a batch writer.\nWrite the entire stream for this blob to a batch writer.\nWrite the entire blob to a slice writer and to an optional …\nWrite the entire blob to a slice writer and to an optional …\nProgress state for a single blob\nState of a single blob in transfer\nDownload has finished\nDownload is pending\nThe identifier for progress events.\nDownload is in progress\nAccumulated progress state of a transfer.\nNumber of children (only applies to hashseqs, None for raw …\nChildren if the root blob is a hash seq, empty for raw …\nWhether we are connected to a node\nChild being transferred at the moment.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nGet a blob state by its <code>BlobId</code> in this transfer.\nGet the blob state currently being transferred.\nThe hash of this blob.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nRanges already available locally at the time of starting …\nCreate a new, empty transfer state.\nCreate a new <code>BlobState</code>.\nUpdate the state with a new <code>DownloadProgress</code> event for …\nThe current state of the blob transfer.\nProgress ids for individual blobs.\nGet state of the root blob of this transfer.\nThe root blob of this transfer (may be a hash seq),\nThe size of this blob. Only known if the blob is partially …\nProbe for a single chunk of a blob.\nGiven a hash of a hash seq, get the hash seq and the …\nGet the claimed size of a blob from a peer.\nGet the verified size of a blob from a peer.\nGiven a sequence of sizes of children, generate a range …\nA sequence of links, backed by a <code>Bytes</code> object.\nIterator over the hashes in a <code>HashSeq</code>.\nStream over the hashes in a <code>HashSeq</code>.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nGet the hash at the given index.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nConvert an iterator of anything into <code>FallibleIterator</code> by …\nGet the underlying bytes.\nCheck if this sequence is empty.\nIterate over the hashes in this sequence.\nGet the number of hashes in this sequence.\nCreate a new sequence of hashes.\nGet the next hash in the sequence.\nParse a sequence of hashes.\nGet and remove the first hash in this sequence.\nSkip a number of hashes in the sequence.\nConvert an iterator of <code>Result</code>s into <code>FallibleIterator</code> by …\nEnum of metrics for the module\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nThe ALPN used with quic for the iroh bytes protocol.\nReasons to close connections or stop streams.\nA <code>RangeSpec</code> selecting nothing from the blob.\nA get request for a blob or collection\nA request\nMaximum message size is limited to 100MiB for now.\nAn iterator over blobs in the sequence with a non-empty …\nThe provider is terminating.\nA chunk range specification as a sequence of chunk offsets.\nA chunk range specification for a sequence of blobs.\nA request to the provider\nThe provider has received the request.\nThe <code>RecvStream</code> was dropped.\nUnknown error_code, can not be converted into <code>Closed</code>.\nCreates a <code>RangeSpec</code> selecting the entire blob.\nA <code>RangeSpecSeq</code> containing all chunks from all blobs.\nRequest a collection and all its children\nIf this range seq describes a range for a single item, …\nA <code>RangeSpecSeq</code> containing no chunks from any blobs in the …\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nConvenience function to create a <code>RangeSpecSeq</code> from a …\nConvenience function to create a <code>RangeSpecSeq</code> from a …\nblake3 hash\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nConvert an iterator of anything into <code>FallibleIterator</code> by …\nChecks if this <code>RangeSpec</code> selects all chunks in the blob.\nChecks if this <code>RangeSpec</code> does not select any chunks in the …\nAn infinite iterator of range specs for blobs in the …\nAn iterator over blobs in the sequence with a non-empty …\nRequest the last chunk of a single blob\nRequest the last chunk for all children\nCreates a new <code>RangeSpec</code> from a range set.\nCreates a new range spec sequence from a sequence of range …\nRequest a blob or collection with specified ranges\nThe range of data to request\nThe close reason as bytes. This is a valid utf8 string …\nRequest just a single blob\nCreates a <code>ChunkRanges</code> from this <code>RangeSpec</code>.\nConvert an iterator of <code>Result</code>s into <code>FallibleIterator</code> by …\nWe got an error and need to abort.\nProgress updates for the add operation.\nWe are done with the whole operation.\nA new client connected to the node.\nA request was received from a client.\nWe are done with <code>id</code>, and the hash is <code>hash</code>.\nEvents emitted by the provider informing about the current …\nTrait for sending events.\nAn item was found with name <code>name</code>, from now on referred to …\nA request was received from a client.\nThe requested data was not found\nWe got progress ingesting item <code>id</code>.\nA helper struct that combines a quinn::SendStream with …\nThe requested data was sent\nStatus  of a send operation\nA new collection or tagged blob has been added\nA request was aborted because the client disconnected.\nA blob in a sequence was transferred.\nA request was completed and the data was sent to the …\nA sequence of hashes has been found and is being …\nThe stats for a transfer of a collection or blob.\nThe total duration of the transfer.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nHandle a single connection.\nHandle a single standard get request.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nStats for reading from disk.\nRead the request from the getter.\nSend an event.\nStats for sending to the client.\nSend a blob to the client.\nTransfers the collection &amp; blob data.\nThe format of the added data.\nThe hash of the entry.\nThe hash of the created data.\nA new unique id for this entry.\nThe unique id of the entry.\nThe unique id of the entry.\nThe name of the entry.\nThe offset of the progress, in bytes.\nThe size of the entry in bytes.\nThe tag of the added data.\nAn unique connection id.\nAn unique connection id.\nAn unique connection id.\nAn unique connection id.\nAn unique connection id.\nAn unique connection id.\nThe quic connection id.\nThe format of the added data\nThe hash of the added data\nThe hash for which the client wants to receive data.\nThe hash of the blob\nThe index of the blob in the sequence.\nThe size of the custom get request.\nThe number of blobs in the sequence.\nAn identifier uniquely identifying this transfer request.\nAn identifier uniquely identifying this transfer request.\nAn identifier uniquely identifying this transfer request.\nAn identifier uniquely identifying this transfer request.\nAn identifier uniquely identifying this transfer request.\nAn identifier uniquely identifying this request.\nThe size of the blob transferred.\nstatistics about the transfer\nstatistics about the transfer. This is None if the transfer\nThe tag of the added data\nWe got an error and need to abort.\nWe got an error and need to abort.\nWe are done with the whole operation.\nAn async batch interface for writing bao content items to …\nThe size of a bao file\nThe hash refers to any blob and will be exported to a …\nThe hash refers to a <code>crate::format::collection::Collection</code> …\nThe entry is completely available.\nProgress updates for the validate operation\nThis mode will copy the file into the database before …\nThis mode will copy the file to the target directory.\nProgress when copying the file to the store\nA custom event (info)\nA custom event (debug)\nA custom non critical error\nA custom non critical error\nA fallible but owned iterator over the entries in a store.\nDone exporting\nConsistency check ended\nWe started validating a complete entry\nThe entry type. An entry is a cheaply cloneable handle …\nWe are done with <code>id</code>\nAn entry that is possibly writable\nWe got progress ingesting item <code>id</code>.\nThe availability status of an entry in a store.\nAn unrecoverable error during GC\nAn unrecoverable error during GC\nErrors, something is very wrong\nDatabase events\nThe expected format of a hash being exported.\nThe import mode describes how files will be imported.\nExport trogress callback\nFound a path\nA GC was completed\nAn event related to GC\nA GC was started\nAn event related to GC\nThe import mode describes how files will be imported.\nProgress messages for an import operation\nInfo messages\nA generic map from hashes to bao blobs (blobs with bao …\nAn entry for one hash in a bao map\nA partial entry\nA mutable bao map.\nThe entry is not in the store.\nDone computing the outboard\nProgress when computing the outboard\nThe entry is partially available.\nWe started validating an entry\nWe are done with <code>id</code>\nWe got progress ingesting item <code>id</code>.\nProgress when copying the file to the target\nExtension of <code>Map</code> to add misc methods used by the rpc calls.\nLevel for generic validation messages\nDetermined the size\nStarting to export to a file\nConsistency check started\nstarted validating\nThe mutable part of a Bao store.\nVery unimportant info messages\nThis mode will try to reference the file in place and …\nThis mode will try to move the file to the target …\nA remote side told us the size, but we have insufficient …\nConsistency check update\nProgress updates for the validate operation\nWe have verified the size.\nWarnings, something is not quite right\nGet a batch writer\nlist all blobs in the database. This includes both raw …\nPerform a consistency check on the database\nCreate a new tag\nA future that resolves to a reader that can be used to …\nphysically delete the given hashes from the store.\nFind out if the data behind a <code>hash</code> is complete, partial, …\nSync version of <code>entry_status</code>, for the doc sync engine …\nThis trait method extracts a file to a local path.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nredb backed storage\nTraverse all roots recursively and mark them as live.\nTraverse all roots recursively and mark them as live.\nNotify the store that a new gc phase is about to start.\nRemove all blobs that are not marked as live.\nRemove all blobs that are not marked as live.\nGet an entry for a hash.\nGet an existing entry as an EntryMut.\nGet an existing partial entry, or create a new one.\nThe hash of the entry.\nImport data from memory.\nThis trait method imports a file from a local path.\nImport data from an async byte reader.\nImport data from an async byte reader.\nImport data from a stream of bytes.\nUpgrade a partial entry to a complete entry.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nReturns <code>true</code> if the entry is complete.\nA full in memory database for iroh-blobs\nCreate a new <code>BaoFileSize</code> with the given size and …\nA future that resolves to a reader that can be used to …\nlist partial blobs in the database\nA readonly in memory database for iroh-blobs, usable for …\nSet a tag\nShutdown the store.\nThe size of the entry.\nSync the written data to permanent storage, if applicable. …\nlist all tags (collections or other explicitly added …\nCreate a temporary pin for this store\nTemp tags\nValidate the database\nValidate the database\nGet just the value, no matter if it is verified or not.\nWrite a batch of bao content items to the underlying …\nThe entry this message is about, if any\nThe level of the message\nThe message\nAn error if we failed to validate the entry.\nthe hash of the entry\nthe hash of the entry\na new unique id for this entry\nThe unique id of the entry.\nThe unique id of the entry.\na new unique id for this entry\nThe unique id of the entry.\nThe unique id of the entry.\nThe offset of the progress, in bytes.\nThe offset of the progress, in bytes.\nlocation of the entry.\nlocation of the entry.\nAvailable ranges.\nThe size of the entry, in bytes.\nThe best known size of the entry, in bytes.\nThe total number of entries to validate\nAlways inline everything\nOptions for transaction batching.\nUse BaoFileHandle as the entry type for the map.\nParameters for importing from a flat store\nOptions for inlining small complete data or outboards.\nDo not inline anything, ever.\nOptions for the file store.\nOptions for directories used by the file store.\nStorage that is using a redb database for small files and …\nTransaction batching options.\nComplete data files\nPath to the directory where data and outboard files are …\nDump the entire content of the database to stdout.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nImport from a v0 or v1 flat store, for backwards …\nInline storage options.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nLoad or create a new store.\nMaximum data size to inline.\nMaximum outboard size to inline.\nMaximum number of actor messages to batch before creating …\nMaximum duration to wait before committing a read …\nMaximum number of actor messages to batch before …\nMaximum duration to wait before committing a write …\nMetadata files such as the tags table\nCreate a new store with custom options.\nOwned data path\nOwned outboard path\nPartial data files\nPath options.\nEnsure that all operations before the sync are processed …\nPath to the directory where temp files are stored. This …\nTransform all entries in the store. This is for testing …\nUpdate the inline options.\nAn in memory entry\nA fully featured in memory database for iroh-blobs, …\nReturns the argument unchanged.\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCreate a new in memory store\nThe MapEntry implementation for Store.\nA readonly in memory database for iroh-blobs.\nReturns the argument unchanged.\nReturns the argument unchanged.\nGet the bytes associated with a hash, if they exist.\nimport a byte slice\nInsert a new entry into the database, and return the hash …\nInsert multiple entries into the database, and return the …\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCreate a new Store from a sequence of entries.\nA tag will be automatically generated\nA file\nWe got it all in memory\nThis is a general purpose Either, just like Result, except …\nThe tag is explicitly named\nOption for commands that allow setting a tag\nA file that is sparse in memory\nA tag\nA trait for things that can track liveness of blobs and …\nTrait used from temp tags to notify an abstract store that …\nA hash and format pair that is protected from garbage …\nTurn a reference to a MemOrFile into a MemOrFile of …\nGet this as a weak reference for use in temp tags\nCreate a new tag that does not exist yet.\nThe format of the pinned item\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nThe hash of the pinned item\nThe hash of the pinned item\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nGet the data and the valid ranges\nUtilities for working with tokio io\nTrue if this is a Mem\nKeep the item alive until the end of the process\nA local task pool with proper shutdown\nMap the file part of this MemOrFile\nMap the memory part of this MemOrFile\nGet the mem part\nCreate a new, empty SparseMemFile\nCreate a new temp tag for the given hash and format\nCalled on creation of a temp tag\nCalled on drop\nPersist the SparseMemFile to a WriteAt\nUtilities for reporting progress.\nGet the size of the MemOrFile\nCreate a new temp tag for the given hash and format\nGet the number of bytes given a set of chunk ranges and …\nTry to map the file part of this MemOrFile\nA reader that tracks the number of bytes read\nA writer that tracks the number of bytes written\nGet the number of bytes read\nGet the number of bytes written\nReturns the argument unchanged.\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nGet the inner reader\nGet the inner writer\nWrap a reader in a tracking reader\nWrap a writer in a tracking writer\nTask was dropped, either due to a panic or because the …\nLocal task pool configuration\nA local task pool with proper shutdown\nA handle to a <code>LocalPool</code>\nLog the panic and continue\nWhat to do when a panic occurs in a pool thread\nFuture returned by <code>LocalPoolHandle::spawn</code> and …\nLog the panic and immediately shut down the pool.\nErrors for spawn failures\nAbort the task\nA future that resolves when the pool is cancelled\nGently shut down the pool\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nGet a cheaply cloneable handle to the pool\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCreate a new local pool with the given config.\nIgnore panics in pool threads\nImmediately stop polling all tasks and wait for all …\nCreate a new local pool with a single std thread.\nSpawn a task in the pool and await the result.\nSpawn a task in the pool.\nPrefix for thread names\nNumber of threads in the pool\nSpawn a task in the pool and return a future that resolves …\nSpawn a task in the pool.\nSpawn a task in the pool.\nGet the number of tasks in the queue\nA progress sender that uses an async channel.\nA boxed progress sender\nContains the error value\nA slice writer that adds a fallible progress callback.\nA progress sender that uses a flume channel.\nAn id generator, to be combined with a progress sender.\nA no-op progress sender.\nThe message being sent.\nContains the success value\nAn error that can occur when sending progress messages.\nA result type for progress sending.\nA general purpose progress sender. This should be usable …\nA slice writer that adds a synchronous progress callback.\nThe receiver was dropped.\nTransform the message type by filter-mapping to the type …\nTransform the message type by mapping to the type of this …\nSend a message and block if the receiver is full.\nCreate a boxed progress sender to get rid of the concrete …\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nReturn the inner writer\nReturn the inner writer.\nCreate a new progress sender from a flume sender.\nCreate a new progress sender from an async channel sender.\nCreate a new <code>ProgressSliceWriter</code> from an inner writer and …\nCreate a new <code>ProgressSliceWriter</code> from an inner writer and …\nGet a new unique id\nReturns true if <code>other</code> sends on the same <code>flume</code> channel as …\nReturns true if <code>other</code> sends on the same <code>async_channel</code> …\nSend a message and wait if the receiver is full.\nTry to send a message and drop it if the receiver is full.\nTransform the message type by filter-mapping to the type …\nTransform the message type by mapping to the type of this …")