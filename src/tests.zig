const assert = @import("std").debug.assert;
const eql = @import("std").mem.eql;
const Blowfish = @import("lib.zig").Blowfish;

test "comptime" {
    comptime {
        var foo = Blowfish.init(([_]u8{ 1, 2, 3, 4 })[0..]) catch unreachable;
        var arr = [8]u8{ 1, 2, 3, 4, 9, 8, 7, 6 };
        var arr2 = arr;
        foo.encryptBlock(&arr2);
        foo.decryptBlock(&arr2);
        assert(eql(u8, &arr, &arr2));
    }
}

test "rt block" {
    var foo = Blowfish.init(([_]u8{ 1, 2, 3, 4 })[0..]) catch unreachable;
    var arr = [8]u8{ 1, 2, 3, 4, 9, 8, 7, 6 };
    var arr2 = arr;
    foo.encryptBlock(&arr2);
    foo.decryptBlock(&arr2);
    assert(eql(u8, &arr, &arr2));
}

test "rt unaligned block" {
    var foo = Blowfish.init(([_]u8{ 1, 2, 3, 4 })[0..]) catch unreachable;
    var arr = [9]u8{ 1, 2, 3, 4, 5, 9, 8, 7, 6 };
    var arr2 = arr[1..];
    foo.encryptBlock(arr2);
    foo.decryptBlock(arr2);
    assert(eql(u8, arr[1..], arr2));
}
