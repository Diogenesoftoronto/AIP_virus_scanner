const std = @import("std");
const clam = @import("c.zig");

pub fn fatalf(comptime str: []const u8, args: anytype) void {
    std.debug.print("{s} {any}", .{ str, args });
    std.os.exit(1);
}

pub fn fatal(comptime str: []const u8) void {
    std.debug.print(str, .{});
    std.os.exit(1);
}

pub const ScannedFileResults = struct {
    file: std.fs.File,
    virus: []u8,
};

pub const FreeClamEngine = fn (?*clam.cl_engine) callconv(.C) c_uint;

pub fn freeEngine(comptime free: FreeClamEngine, engine: ?*clam.cl_engine) void {
    const is_free = free(engine);
    if (is_free != clam.CL_SUCCESS) {
        fatal("Freeing the engine has failed");
    }
}

pub fn cStrToSlice(c_str: [*c]u8) []u8 {
    const length = std.mem.sliceTo(c_str, 0).len;
    return c_str[0..length :0];
}

pub fn main() !void {
    var arena: std.heap.ArenaAllocator = std.heap.ArenaAllocator.init(std.heap.c_allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const stdout = std.io.getStdOut().writer();
    var maybefd: ?std.fs.File = undefined;
    var file: []const u8 = undefined;

    const args = try std.process.argsAlloc(alloc);
    defer std.process.argsFree(alloc, args);

    try stdout.print("Thanks for the file AIP. ", .{});
    const all_paths: [][]const u8 = @as([][]const u8, args);
    var path: []const u8 = undefined;
    var dir_entries: []?std.fs.Dir.IterableDir = null;
    for (all_paths) |ele| {
        if (std.fs.cwd().openDir(ele, .{ .access_sub_paths = true })) |opened_dir| {
            dir_entries = opened_dir.iterableDir();
            path = ele;
        } else |err| {
            switch (err) {
                error.NotDir => {
                    file = std.fs.path.basename(path);
                    return;
                },
                else => {
                    fatalf("Unexpected error occured.", err);
                },
            }
        }
    }
    if (path)
        maybefd = std.fs.cwd().openFile(path, .{
            .mode = .read_only,
        });

    const fd = maybefd catch |err| {
        switch (err) {
            error.FileNotFound => {
                fatal("\nThe file could not be found.\n", .{});
            },
            else => {
                fatal("There were other unexpected errors {}", .{err});
            },
        }
    };
    defer fd.close();

    try stdout.print("\nInitializing Clamav\n", .{});
    const is_initialized = clam.cl_init(clam.CL_INIT_DEFAULT);
    if (is_initialized != clam.CL_SUCCESS) {
        fatal("Failed to initialize Clamav. Got: {}", .{is_initialized});
    }
    try stdout.print("Clamav Initialisation complete.\n", .{});

    try stdout.print("Clamav Engine Starting.\n", .{});
    const engine: ?*clam.cl_engine = clam.cl_engine_new();
    defer freeEngine(clam.cl_engine_free, engine);
    if (engine == null) {
        fatal("The engine could not begin.", .{});
    }
    try stdout.print("Clamav Engine has started successfully.\n", .{});

    try stdout.print("Acquire the viral database. ", .{});

    var sigs: c_uint = undefined;
    const is_loaded = clam.cl_load(clam.cl_retdbdir(), engine, &sigs, clam.CL_DB_STDOPT);
    if (is_loaded != clam.CL_SUCCESS) {
        fatal("\nDatabase failed to load.\n", .{});
    }
    try stdout.print("Viral database acquired.\n", .{});

    try stdout.print("Compiling the engine. ", .{});
    const is_compiled = clam.cl_engine_compile(engine);
    if (is_compiled != clam.CL_SUCCESS) {
        fatal("\nThe engine failed to compile. \n", .{});
    }
    try stdout.print("Engine has successfully compiled.\n", .{});

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
    const c_path: [*c]u8 = &path[0];
    var file_name = std.fs.path.basename(path);
    var scan_results: ScannedFileResults = .{
        .file = fd,
        .virus = undefined,
    };

    try stdout.print("Now scanning the files for viruses.\n", .{});
    const is_infected_with_virus: clam.cl_error_t = clam.cl_scandesc(fd.handle, c_path, &virname, &size, engine, &options);
    if (is_infected_with_virus == clam.CL_VIRUS) {
        // Add this to a virus array for the virus scan
        scan_results.virus = cStrToSlice(virname);
        try stdout.print("We got a virus! It's name is: {s}, it is in {s}.\n", .{ scan_results.virus, file_name });
    } else if (is_infected_with_virus == clam.CL_CLEAN) {
        // const file_metadata = try fd.metadata();
        // _ = file_metadata;
        try stdout.print("No viruses have been found in {!s}\n", .{file_name});
    }
    try stdout.print("Finished scanning the file for viruses.\n", .{});

    try stdout.print("\nThe program is complete, now exiting.", .{});
    std.os.exit(0);
}
