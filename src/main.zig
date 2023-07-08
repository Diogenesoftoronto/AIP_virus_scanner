const std = @import("std");
const clam = @import("c.zig");

pub fn main() !void {
    // const CL = enum { succes, failure, init_default, max_engine_scantime, db_stdopt };
    // _ = CL;
    const stdout = std.io.getStdOut().writer();
    const stdin = std.io.getStdIn().reader();

    try stdout.print("Gimme a file you AIP", .{});

    var read_buf: [80]u8 = undefined;

    if (stdin.readUntilDelimiterOrEof(read_buf[0..], '\n')) |path| {
        try stdout.print("Here is the file {?s}", .{path});
        const true_path = path orelse "~/aip_path";
        var fd: std.fs.File = try std.fs.cwd().openFile(true_path, .{
            .mode = .read_only,
        });
        defer fd.close();
    } else |err| switch (err) {
        error.StreamTooLong => std.debug.print("Your file name was too long, try a shorter file.", .{}),
        else => std.debug.print("The were other unexpected errors {}", .{err}),
        // error.EndOfStream => std.debug.print("The stream terminated unexpectedly."),
    }

    var ret = clam.cl_init(clam.CL_INIT_DEFAULT);
    if (ret != clam.CL_SUCCESS) {
        std.debug.print("Failed to initialize clamav.", .{});
        std.os.exit(1);
    }

    var engine = clam.cl_engine_new();
    if (engine == null) {
        std.debug.print("The engine could not begin.", .{});
        std.os.exit(1);
    }
}
