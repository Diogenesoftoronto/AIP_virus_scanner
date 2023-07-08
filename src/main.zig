const std = @import("std");
const clam = @import("c.zig");

pub const FreeClamEngine = fn (?*clam.cl_engine) callconv(.C) c_uint;
pub fn freeEngine(comptime free: FreeClamEngine, engine: ?*clam.cl_engine) void {
    const is_free = free(engine);
    if (is_free != clam.CL_SUCCESS) {
        std.debug.print("Freeing the engine has failed", .{});
        std.os.exit(1);
    }
}

pub fn main() !void {
    const stdout = std.io.getStdOut().writer();
    const stdin = std.io.getStdIn().reader();
    var true_path: []u8 = undefined;

    try stdout.print("Gimme a file you AIP: ", .{});

    var read_buf: [80]u8 = undefined;

    if (stdin.readUntilDelimiterOrEof(read_buf[0..], '\n')) |path| {
        try stdout.print("Here is the file -> {?s}", .{path});
        true_path = path.?;
    } else |err| switch (err) {
        error.StreamTooLong => std.debug.print("Your file name was too long, try a shorter file.", .{}),
        else => std.debug.print("The were other unexpected errors {}", .{err}),
    }

    const fd: std.fs.File = try std.fs.cwd().openFile(true_path, .{
        .mode = .read_only,
    });
    defer fd.close();

    try stdout.print("\nInitializing Clamav\n", .{});
    const is_initialized = clam.cl_init(clam.CL_INIT_DEFAULT);
    if (is_initialized != clam.CL_SUCCESS) {
        std.debug.print("Failed to initialize Clamav. Got: {}", .{is_initialized});
        std.os.exit(1);
    }
    try stdout.print("Clamav Initialisation complete.\n", .{});

    try stdout.print("Clamav Engine Starting.\n", .{});
    const engine: ?*clam.cl_engine = clam.cl_engine_new();
    defer freeEngine(clam.cl_engine_free, engine);
    if (engine == null) {
        std.debug.print("The engine could not begin.", .{});
        std.os.exit(1);
    }
    try stdout.print("Clamav Engine has started successfully.\n", .{});

    var options: clam.cl_scan_options = .{
        .general = 0,
        .parse = 0,
        .heuristic = 0,
        .mail = 0,
        .dev = 0,
    };

    options.general |= clam.CL_SCAN_GENERAL_HEURISTICS;
    options.heuristic |= 1;
    // std.mem.set(clam.cl_scan_options, options, 0);
    var virname: [*c]u8 = undefined;
    var size: u64 = undefined;

    // Converting the file handler from a zig style string array to a c style null terminated one
    const c_path: [*c]u8 = &true_path[0];

    try stdout.print("Now scanning the files for viruses\n", .{});
    const is_infected_with_virus: clam.cl_error_t = clam.cl_scandesc(fd.handle, c_path, &virname, &size, engine, &options);
    _ = is_infected_with_virus;
}
