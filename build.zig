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

    // we need to build secp256k1 in PIC to link it to the shared object
    sig.builder.dependency("secp256k1", .{
        .target = target,
        .optimize = optimize,
    }).artifact("secp256k1").root_module.pic = true;

    var protoc_step = protobuf.RunProtocStep.create(b, pb.builder, target, .{
        .destination_directory = b.path("src/proto"),
        .source_files = &.{
            "protosol/proto/elf.proto",
            "protosol/proto/vm.proto",
            "protosol/proto/shred.proto",
        },
        .include_directories = &.{"protosol/proto"},
    });

    const test_exe = b.addTest(.{
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .optimize = optimize,
    });
    test_exe.root_module.addImport("protobuf", pb.module("protobuf"));
    test_exe.root_module.addImport("sig", sig.module("sig"));
    const test_step = b.step("test", "");
    test_step.dependOn(&b.addRunArtifact(test_exe).step);

    const lib = b.addSharedLibrary(.{
        .name = "solfuzz_sig",
        .target = target,
        .optimize = optimize,
        .root_source_file = b.path("src/lib.zig"),
    });
    lib.root_module.omit_frame_pointer = false;
    lib.root_module.addImport("sig", sig.module("sig"));
    lib.root_module.addImport("protobuf", pb.module("protobuf"));
    lib.step.dependOn(&protoc_step.step);
    b.installArtifact(lib);
}
