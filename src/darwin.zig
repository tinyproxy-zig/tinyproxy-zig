// Defined here until https://github.com/ziglang/zig/pull/24224 is merged
// see https://github.com/apple/darwin-xnu/blob/main/bsd/sys/socket.h#L991
pub const MSG = struct {
    /// process out-of-band data
    pub const OOB = 0x1;
    /// peek at incoming message
    pub const PEEK = 0x2;
    /// send without using routing tables
    pub const DONTROUTE = 0x4;
    /// data completes record
    pub const EOR = 0x8;
    /// data discarded before delivery
    pub const TRUNC = 0x10;
    /// control data lost before delivery
    pub const CTRUNC = 0x20;
    /// wait for full request or error
    pub const WAITALL = 0x40;
    /// this message should be nonblocking
    pub const DONTWAIT = 0x80;
    /// data completes connection
    pub const EOF = 0x100;
    /// wait up to full request, may return partial
    pub const WAITSTREAM = 0x200;
    /// Start of 'hold' seq; dump so_temp, deprecated
    pub const FLUSH = 0x400;
    /// Hold frag in so_temp, deprecated
    pub const HOLD = 0x800;
    /// Send the packet in so_temp, deprecated
    pub const SEND = 0x1000;
    /// Data ready to be read
    pub const HAVEMORE = 0x2000;
    /// Data remains in current pkt
    pub const RCVMORE = 0x4000;
    /// Fail receive if socket address cannot be allocated
    pub const NEEDSA = 0x10000;
    /// do not generate SIGPIPE on EOF
    pub const NOSIGNAL = 0x80000;
    /// Inherit upcall in sock_accept
    pub const USEUPCALL = 0x80000000;
};
