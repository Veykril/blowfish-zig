const sboxes = @import("sboxes.zig");

pub const InvalidKeySizeError = error{InvalidKeySizeError};

pub const Blowfish = struct {
    p: [18]u32 = sboxes.P,
    s: [4][256]u32 = sboxes.S,

    const Pair = packed struct { l: u32, r: u32 };

    pub fn init(key: []const u8) InvalidKeySizeError!Blowfish {
        if (key.len < 4 or 56 < key.len) {
            return error.InvalidKeySizeError;
        }
        var this = Blowfish{};
        expand_key(&this, key);
        return this;
    }

    pub fn encrypt_block(self: *const Blowfish, block: *[8]u8) void {
        var bpair = @bitCast(Pair, block.*);
        var out = self.encrypt(bpair);
        block.* = @bitCast([8]u8, out);
    }

    pub fn decrypt_block(self: *const Blowfish, block: *[8]u8) void {
        var bpair = @bitCast(Pair, block.*);
        var out = self.decrypt(bpair);
        block.* = @bitCast([8]u8, out);
    }

    fn expand_key(self: *Blowfish, key: []const u8) void {
        @setEvalBranchQuota(2 << 13);
        var key_pos: usize = 0;
        for (self.p) |*val| {
            val.* ^= next_u32_wrap(key, &key_pos);
        }
        var lr: Pair = .{ .l = 0, .r = 0 };
        var i: u8 = 0;
        while (i < 9) : (i += 1) {
            lr = self.encrypt(lr);
            self.p[2 * i] = lr.l;
            self.p[2 * i + 1] = lr.r;
        }
        for (self.s) |*sub| {
            var k: usize = 0;
            while (k < 128) : (k += 1) {
                lr = self.encrypt(lr);
                sub.*[2 * k] = lr.l;
                sub.*[2 * k + 1] = lr.r;
            }
        }
    }

    fn encrypt(self: *const Blowfish, p: Pair) Pair {
        var l = p.l;
        var r = p.r;
        var i: u8 = 0;
        while (i < 8) : (i += 1) {
            l ^= self.p[2 * i];
            r ^= self.round_function(l);
            r ^= self.p[2 * i + 1];
            l ^= self.round_function(r);
        }
        l ^= self.p[16];
        r ^= self.p[17];
        return Pair{ .l = r, .r = l };
    }

    fn decrypt(self: *const Blowfish, p: Pair) Pair {
        var l = p.l;
        var r = p.r;
        var i: u8 = 8;
        while (i > 0) : (i -= 1) {
            l ^= self.p[2 * i + 1];
            r ^= self.round_function(l);
            r ^= self.p[2 * i];
            l ^= self.round_function(r);
        }
        l ^= self.p[1];
        r ^= self.p[0];
        return Pair{ .l = r, .r = l };
    }

    fn round_function(self: *const Blowfish, x: u32) u32 {
        var a = self.s[0][(x >> 24)];
        var b = self.s[1][(x >> 16) & 0xFF];
        var c = self.s[2][(x >> 8) & 0xFF];
        var d = self.s[3][x & 0xFF];
        return ((a +% b) ^ c) +% d;
    }
};

fn next_u32_wrap(buf: []const u8, offset: *usize) u32 {
    var v: u32 = 0;
    var i: u32 = 0;
    while (i < 4) : (i += 1) {
        if (offset.* >= buf.len) {
            offset.* = 0;
        }
        v = @intCast(u32, (v << 8) | buf[offset.*]);
        offset.* += 1;
    }
    return v;
}
