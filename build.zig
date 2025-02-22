const std = @import("std");
const protobuf = @import("pb");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const sig = b.dependency("sig", .{
        .target = target,
        .optimize = optimize,
        .@"enable-tsan" = false,
        .blockstore = .hashmap,
    });
    const pb = b.dependency("pb", .{
        .target = target,
        .optimize = optimize,
    });

    var protoc_step = protobuf.RunProtocStep.create(b, pb.builder, target, .{
        .destination_directory = b.path("src/proto"),
        .source_files = &.{
            "protosol/proto/elf.proto",
            "protosol/proto/vm.proto",
            "protosol/proto/shred.proto",
        },
        .include_directories = &.{"protosol/proto"},
    });

    const lib = b.addSharedLibrary(.{
        .name = "elf",
        .target = target,
        .optimize = optimize,
        .root_source_file = b.path("src/lib.zig"),
    });
    lib.root_module.addImport("sig", sig.module("sig"));
    lib.root_module.addImport("protobuf", pb.module("protobuf"));
    lib.step.dependOn(&protoc_step.step);
    b.installArtifact(lib);
}
