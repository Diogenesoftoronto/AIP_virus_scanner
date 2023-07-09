const std = @import("std");
const clam = @import("c.zig");

pub const ScannedFileResults = struct {
    file: std.fs.File,
    virus: []u8,
};

pub const FreeClamEngine = fn (?*clam.cl_engine) callconv(.C) c_uint;

pub fn freeEngine(comptime free: FreeClamEngine, engine: ?*clam.cl_engine) void {
    const is_free = free(engine);
    if (is_free != clam.CL_SUCCESS) {
        std.debug.print("Freeing the engine has failed", .{});
        std.os.exit(1);
    }
}

pub fn cStrToSlice(c_str: [*c]u8) []u8 {
    const length = std.mem.sliceTo(c_str, 0).len;
    return c_str[0..length :0];
}

pub fn main() !void {
    // var arena: std.heap.ArenaAllocator = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    // defer arena.deinit();
    // const alloc = arena.allocator();

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

    const maybefd = std.fs.cwd().openFile(true_path, .{
        .mode = .read_only,
    });

    const fd = maybefd catch |err| {
        switch (err) {
            error.FileNotFound => {
                std.debug.print("\nThe file could not be found.\n", .{});
                std.os.exit(1);
            },
            else => {
                std.debug.print("The were other unexpected errors {}", .{err});
                std.os.exit(1);
            },
        }
    };
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

    var virname: [*c]u8 = undefined;
    var size: u64 = undefined;

    // Converting the file handler from a zig style string array to a c style null terminated one
    const c_path: [*c]u8 = &true_path[0];

    var scan_results: ScannedFileResults = .{
        .file = fd,
        .virus = undefined,
    };

    try stdout.print("Now scanning the files for viruses.\n", .{});
    const is_infected_with_virus: clam.cl_error_t = clam.cl_scandesc(fd.handle, c_path, &virname, &size, engine, &options);
    if (is_infected_with_virus == clam.CL_VIRUS) {
        // Add this to a virus array for the virus scan
        scan_results.virus = cStrToSlice(virname);
        try stdout.print("We got a virus! It's name is: {s}, it is in {d}.\n", .{ scan_results.virus, std.fs.path.basename(true_path) });
    } else if (is_infected_with_virus == clam.CL_CLEAN) {
        // const file_metadata = try fd.metadata();
        // _ = file_metadata;
        try stdout.print("No viruses have been found in {!s}\n", .{std.fs.path.basename(true_path)});
    }
    try stdout.print("Finished scanning the file for viruses.\n", .{});

    try stdout.print("\nThe program is complete, now exiting.", .{});
    std.os.exit(0);
}
