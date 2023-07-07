const std = @import("std");
const clam = @import("c.zig");

pub fn main() !void {
    _ = clam.cl_init(0);
    var engine = clam.cl_engine_new();
    _ = clam.cl_engine_free(engine);
}
