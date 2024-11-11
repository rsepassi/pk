const std = @import("std");

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const lib = b.addStaticLibrary(.{
        .name = "uv",
        .target = target,
        .optimize = optimize,
    });
    lib.addIncludePath(b.path("include"));
    lib.addIncludePath(b.path("src"));
    lib.linkLibC();

    var cflags = std.ArrayList([]const u8).init(b.allocator);
    try cflags.appendSlice(base_flags);

    if (target.result.os.tag == .macos) {
        try cflags.appendSlice(mac_flags);
        lib.addIncludePath(b.path("src/unix"));
        lib.addCSourceFiles(.{ .files = base_srcs, .flags = cflags.items });
        lib.addCSourceFiles(.{ .files = unix_srcs, .flags = cflags.items });
        lib.addCSourceFiles(.{ .files = mac_srcs, .flags = cflags.items });
    } else if (target.result.os.tag == .linux) {
        try cflags.appendSlice(linux_flags);
        lib.addIncludePath(b.path("src/unix"));
        lib.addCSourceFiles(.{ .files = base_srcs, .flags = cflags.items });
        lib.addCSourceFiles(.{ .files = unix_srcs, .flags = cflags.items });
        lib.addCSourceFiles(.{ .files = linux_srcs, .flags = cflags.items });
    } else if (target.result.os.tag == .freebsd) {
        try cflags.appendSlice(freebsd_flags);
        lib.addIncludePath(b.path("src/unix"));
        lib.addCSourceFiles(.{ .files = base_srcs, .flags = cflags.items });
        lib.addCSourceFiles(.{ .files = unix_srcs, .flags = cflags.items });
        lib.addCSourceFiles(.{ .files = freebsd_srcs, .flags = cflags.items });
    } else if (target.result.os.tag == .windows) {
        try cflags.appendSlice(win_flags);
        lib.addIncludePath(b.path("src/win"));
        lib.addCSourceFiles(.{ .files = base_srcs, .flags = cflags.items });
        lib.addCSourceFiles(.{ .files = win_srcs, .flags = cflags.items });
    } else {
        @panic("unimplemented platform");
    }

    b.installDirectory(.{
        .source_dir = b.path("include"),
        .install_dir = .{ .header = {} },
        .install_subdir = "",
    });
    b.installArtifact(lib);
}

const base_srcs = &.{
    "src/fs-poll.c",
    "src/idna.c",
    "src/inet.c",
    "src/random.c",
    "src/strscpy.c",
    "src/strtok.c",
    "src/thread-common.c",
    "src/threadpool.c",
    "src/timer.c",
    "src/uv-common.c",
    "src/uv-data-getter-setters.c",
    "src/version.c",
};

const base_flags = &.{
    "-std=gnu89",
    "-DPACKAGE_NAME=\"libuv\"",
    "-DPACKAGE_TARNAME=\"libuv\"",
    "-DPACKAGE_VERSION=\"1.49.2\"",
    "-DPACKAGE_STRING=\"libuv 1.49.2\"",
    "-DPACKAGE_BUGREPORT=\"https://github.com/libuv/libuv/issues\"",
    "-DPACKAGE_URL=\"\"",
    "-DPACKAGE=\"libuv\"",
    "-DVERSION=\"1.49.2\"",
    "-DSUPPORT_ATTRIBUTE_VISIBILITY_DEFAULT=1",
    "-DSUPPORT_FLAG_VISIBILITY=1",
    "-DHAVE_STDIO_H=1",
    "-DHAVE_STDLIB_H=1",
    "-DHAVE_STRING_H=1",
    "-DHAVE_INTTYPES_H=1",
    "-DHAVE_STDINT_H=1",
    "-DHAVE_STRINGS_H=1",
    "-DHAVE_SYS_STAT_H=1",
    "-DHAVE_SYS_TYPES_H=1",
    "-DHAVE_UNISTD_H=1",
    "-DSTDC_HEADERS=1",
};

const unix_srcs = &.{
    "src/unix/async.c",
    "src/unix/core.c",
    "src/unix/dl.c",
    "src/unix/fs.c",
    "src/unix/getaddrinfo.c",
    "src/unix/getnameinfo.c",
    "src/unix/loop-watcher.c",
    "src/unix/loop.c",
    "src/unix/pipe.c",
    "src/unix/poll.c",
    "src/unix/process.c",
    "src/unix/random-devurandom.c",
    "src/unix/signal.c",
    "src/unix/stream.c",
    "src/unix/tcp.c",
    "src/unix/thread.c",
    "src/unix/tty.c",
    "src/unix/udp.c",
};

const mac_srcs = &.{
    "src/unix/bsd-ifaddrs.c",
    "src/unix/darwin-proctitle.c",
    "src/unix/darwin.c",
    "src/unix/fsevents.c",
    "src/unix/kqueue.c",
    "src/unix/proctitle.c",
    "src/unix/random-getentropy.c",
};

const mac_flags = &.{
    "-mmacosx-version-min=13.0",
    "-D_DARWIN_USE_64_BIT_INODE=1",
    "-D_DARWIN_UNLIMITED_SELECT=1",
    "-DHAVE_DLFCN_H=1",
    "-DHAVE_PTHREAD_PRIO_INHERIT=1",
};

const linux_srcs = &.{
    "src/unix/linux.c",
    "src/unix/procfs-exepath.c",
    "src/unix/proctitle.c",
    "src/unix/random-getrandom.c",
    "src/unix/random-sysctl-linux.c",
};

const linux_flags = &.{
    "-D_GNU_SOURCE",
    "-DHAVE_DLFCN_H=1",
    "-DHAVE_PTHREAD_PRIO_INHERIT=1",
};

const freebsd_srcs = &.{
    "src/unix/bsd-ifaddrs.c",
    "src/unix/bsd-proctitle.c",
    "src/unix/freebsd.c",
    "src/unix/kqueue.c",
    "src/unix/posix-hrtime.c",
    "src/unix/random-getrandom.c",
};

const freebsd_flags = &.{
    "-D_GNU_SOURCE",
    "-DHAVE_DLFCN_H=1",
    "-DHAVE_PTHREAD_PRIO_INHERIT=1",
};

const win_srcs = &.{
    "src/win/async.c",
    "src/win/core.c",
    "src/win/detect-wakeup.c",
    "src/win/dl.c",
    "src/win/error.c",
    "src/win/fs-event.c",
    "src/win/fs.c",
    "src/win/getaddrinfo.c",
    "src/win/getnameinfo.c",
    "src/win/handle.c",
    "src/win/loop-watcher.c",
    "src/win/pipe.c",
    "src/win/poll.c",
    "src/win/process-stdio.c",
    "src/win/process.c",
    "src/win/signal.c",
    "src/win/stream.c",
    "src/win/tcp.c",
    "src/win/thread.c",
    "src/win/tty.c",
    "src/win/udp.c",
    "src/win/util.c",
    "src/win/winapi.c",
    "src/win/winsock.c",
};

const win_flags = &.{
    "-DWIN32_LEAN_AND_MEAN",
    "-D_FILE_OFFSET_BITS=64",
};

// Windows link: -lws2_32 -luserenv -lole32 -liphlpapi -ldbghelp
